//! Robust notification system with filtering, persistence, and rate limiting.

use crate::error::GdkError;
use crate::protocol::{Notification, NotificationFilter};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, RwLock};
use uuid::Uuid;

/// Configuration for the notification system
#[derive(Debug, Clone)]
pub struct NotificationConfig {
    pub max_buffer_size: usize,
    pub batch_size: usize,
    pub batch_timeout: Duration,
    pub rate_limit_window: Duration,
    pub max_notifications_per_window: usize,
    pub persistence_enabled: bool,
    pub max_persisted_notifications: usize,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 1000,
            batch_size: 10,
            batch_timeout: Duration::from_millis(100),
            rate_limit_window: Duration::from_secs(1),
            max_notifications_per_window: 100,
            persistence_enabled: true,
            max_persisted_notifications: 1000,
        }
    }
}

/// Notification subscription with filtering capabilities
#[derive(Debug, Clone)]
pub struct NotificationSubscription {
    pub id: Uuid,
    pub filter: NotificationFilter,
    pub created_at: Instant,
    pub last_activity: Instant,
}

impl NotificationSubscription {
    pub fn new(filter: NotificationFilter) -> Self {
        let now = Instant::now();
        Self {
            id: Uuid::new_v4(),
            filter,
            created_at: now,
            last_activity: now,
        }
    }

    pub fn should_receive(&self, notification: &Notification) -> bool {
        self.filter.should_include(notification)
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Batched notifications for efficient delivery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationBatch {
    pub notifications: Vec<Notification>,
    pub batch_id: Uuid,
    pub timestamp: u64,
}

impl NotificationBatch {
    pub fn new(notifications: Vec<Notification>) -> Self {
        Self {
            notifications,
            batch_id: Uuid::new_v4(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Rate limiting state for notifications
#[derive(Debug)]
struct RateLimitState {
    window_start: Instant,
    notification_count: usize,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            notification_count: 0,
        }
    }

    fn should_allow(&mut self, config: &NotificationConfig) -> bool {
        let now = Instant::now();
        
        // Reset window if expired
        if now.duration_since(self.window_start) >= config.rate_limit_window {
            self.window_start = now;
            self.notification_count = 0;
        }

        // Check if we're within limits
        if self.notification_count < config.max_notifications_per_window {
            self.notification_count += 1;
            true
        } else {
            false
        }
    }
}

/// Persistent notification storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedNotification {
    pub notification: Notification,
    pub timestamp: u64,
    pub subscription_id: Option<Uuid>,
}

/// Comprehensive notification manager
pub struct NotificationManager {
    config: NotificationConfig,
    subscriptions: Arc<RwLock<HashMap<Uuid, NotificationSubscription>>>,
    senders: Arc<RwLock<HashMap<Uuid, broadcast::Sender<Notification>>>>,
    batch_senders: Arc<RwLock<HashMap<Uuid, broadcast::Sender<NotificationBatch>>>>,
    rate_limits: Arc<RwLock<HashMap<Uuid, RateLimitState>>>,
    notification_buffer: Arc<RwLock<VecDeque<Notification>>>,
    persisted_notifications: Arc<RwLock<VecDeque<PersistedNotification>>>,
    batch_processor_tx: mpsc::Sender<Notification>,
}

impl NotificationManager {
    pub fn new(config: NotificationConfig) -> Self {
        let (batch_tx, batch_rx) = mpsc::channel(config.max_buffer_size);
        
        let manager = Self {
            config: config.clone(),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            senders: Arc::new(RwLock::new(HashMap::new())),
            batch_senders: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            notification_buffer: Arc::new(RwLock::new(VecDeque::new())),
            persisted_notifications: Arc::new(RwLock::new(VecDeque::new())),
            batch_processor_tx: batch_tx,
        };

        // Start batch processing task
        manager.start_batch_processor(batch_rx);
        
        // Start cleanup task
        manager.start_cleanup_task();

        manager
    }

    /// Subscribe to notifications with filtering
    pub async fn subscribe(&self, filter: NotificationFilter) -> Result<(Uuid, broadcast::Receiver<Notification>)> {
        let subscription = NotificationSubscription::new(filter);
        let subscription_id = subscription.id;

        let (tx, rx) = broadcast::channel(self.config.max_buffer_size);
        
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(subscription_id, subscription);
        }

        {
            let mut senders = self.senders.write().await;
            senders.insert(subscription_id, tx);
        }

        {
            let mut rate_limits = self.rate_limits.write().await;
            rate_limits.insert(subscription_id, RateLimitState::new());
        }

        log::debug!("Created notification subscription: {}", subscription_id);
        Ok((subscription_id, rx))
    }

    /// Subscribe to batched notifications
    pub async fn subscribe_batched(&self, filter: NotificationFilter) -> Result<(Uuid, broadcast::Receiver<NotificationBatch>)> {
        let subscription = NotificationSubscription::new(filter);
        let subscription_id = subscription.id;

        let (tx, rx) = broadcast::channel(self.config.max_buffer_size / self.config.batch_size);
        
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(subscription_id, subscription);
        }

        {
            let mut batch_senders = self.batch_senders.write().await;
            batch_senders.insert(subscription_id, tx);
        }

        {
            let mut rate_limits = self.rate_limits.write().await;
            rate_limits.insert(subscription_id, RateLimitState::new());
        }

        log::debug!("Created batched notification subscription: {}", subscription_id);
        Ok((subscription_id, rx))
    }

    /// Unsubscribe from notifications
    pub async fn unsubscribe(&self, subscription_id: Uuid) -> Result<()> {
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.remove(&subscription_id);
        }

        {
            let mut senders = self.senders.write().await;
            senders.remove(&subscription_id);
        }

        {
            let mut batch_senders = self.batch_senders.write().await;
            batch_senders.remove(&subscription_id);
        }

        {
            let mut rate_limits = self.rate_limits.write().await;
            rate_limits.remove(&subscription_id);
        }

        log::debug!("Removed notification subscription: {}", subscription_id);
        Ok(())
    }

    /// Publish a notification to all relevant subscribers
    pub async fn publish(&self, notification: Notification) -> Result<()> {
        // Add to buffer for potential persistence
        {
            let mut buffer = self.notification_buffer.write().await;
            buffer.push_back(notification.clone());
            
            // Limit buffer size
            while buffer.len() > self.config.max_buffer_size {
                buffer.pop_front();
            }
        }

        // Persist if enabled
        if self.config.persistence_enabled {
            self.persist_notification(&notification).await;
        }

        // Send to batch processor
        if let Err(_) = self.batch_processor_tx.send(notification.clone()).await {
            log::warn!("Batch processor channel is full or closed");
        }

        // Send to individual subscribers immediately (for non-batched subscriptions)
        self.send_to_subscribers(notification).await;

        Ok(())
    }

    /// Get notification history for a subscription
    pub async fn get_history(&self, subscription_id: Uuid, limit: usize) -> Result<Vec<PersistedNotification>> {
        let persisted = self.persisted_notifications.read().await;
        let subscription_filter = {
            let subscriptions = self.subscriptions.read().await;
            subscriptions.get(&subscription_id).map(|s| s.filter.clone())
        };

        if let Some(filter) = subscription_filter {
            let filtered: Vec<PersistedNotification> = persisted
                .iter()
                .rev() // Most recent first
                .filter(|pn| filter.should_include(&pn.notification))
                .take(limit)
                .cloned()
                .collect();
            Ok(filtered)
        } else {
            Err(GdkError::invalid_input_simple("Subscription not found".to_string()))
        }
    }

    /// Update subscription filter
    pub async fn update_filter(&self, subscription_id: Uuid, filter: NotificationFilter) -> Result<()> {
        let mut subscriptions = self.subscriptions.write().await;
        if let Some(subscription) = subscriptions.get_mut(&subscription_id) {
            subscription.filter = filter;
            subscription.update_activity();
            Ok(())
        } else {
            Err(GdkError::invalid_input_simple("Subscription not found".to_string()))
        }
    }

    /// Get subscription statistics
    pub async fn get_stats(&self) -> NotificationStats {
        let subscriptions = self.subscriptions.read().await;
        let buffer = self.notification_buffer.read().await;
        let persisted = self.persisted_notifications.read().await;

        NotificationStats {
            active_subscriptions: subscriptions.len(),
            buffered_notifications: buffer.len(),
            persisted_notifications: persisted.len(),
            total_published: 0, // Would need to track this separately
        }
    }

    async fn send_to_subscribers(&self, notification: Notification) {
        let subscriptions = self.subscriptions.read().await;
        let senders = self.senders.read().await;
        let mut rate_limits = self.rate_limits.write().await;

        for (sub_id, subscription) in subscriptions.iter() {
            if subscription.should_receive(&notification) {
                // Check rate limiting
                if let Some(rate_limit) = rate_limits.get_mut(sub_id) {
                    if !rate_limit.should_allow(&self.config) {
                        log::debug!("Rate limit exceeded for subscription: {}", sub_id);
                        continue;
                    }
                }

                // Send notification
                if let Some(sender) = senders.get(sub_id) {
                    if let Err(_) = sender.send(notification.clone()) {
                        log::debug!("Failed to send notification to subscription: {}", sub_id);
                    }
                }
            }
        }
    }

    async fn persist_notification(&self, notification: &Notification) {
        let persisted_notification = PersistedNotification {
            notification: notification.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            subscription_id: None,
        };

        let mut persisted = self.persisted_notifications.write().await;
        persisted.push_back(persisted_notification);

        // Limit persisted notifications
        while persisted.len() > self.config.max_persisted_notifications {
            persisted.pop_front();
        }
    }

    fn start_batch_processor(&self, mut batch_rx: mpsc::Receiver<Notification>) {
        let config = self.config.clone();
        let subscriptions = self.subscriptions.clone();
        let batch_senders = self.batch_senders.clone();
        let rate_limits = self.rate_limits.clone();

        tokio::spawn(async move {
            let mut batch_buffer: Vec<Notification> = Vec::new();
            let mut batch_timer = tokio::time::interval(config.batch_timeout);

            loop {
                tokio::select! {
                    // Receive new notification
                    Some(notification) = batch_rx.recv() => {
                        batch_buffer.push(notification);
                        
                        // Send batch if it's full
                        if batch_buffer.len() >= config.batch_size {
                            Self::send_batch(&batch_buffer, &subscriptions, &batch_senders, &rate_limits, &config).await;
                            batch_buffer.clear();
                        }
                    }
                    
                    // Timeout - send partial batch
                    _ = batch_timer.tick() => {
                        if !batch_buffer.is_empty() {
                            Self::send_batch(&batch_buffer, &subscriptions, &batch_senders, &rate_limits, &config).await;
                            batch_buffer.clear();
                        }
                    }
                }
            }
        });
    }

    async fn send_batch(
        notifications: &[Notification],
        subscriptions: &Arc<RwLock<HashMap<Uuid, NotificationSubscription>>>,
        batch_senders: &Arc<RwLock<HashMap<Uuid, broadcast::Sender<NotificationBatch>>>>,
        rate_limits: &Arc<RwLock<HashMap<Uuid, RateLimitState>>>,
        config: &NotificationConfig,
    ) {
        let subscriptions_guard = subscriptions.read().await;
        let senders_guard = batch_senders.read().await;
        let mut rate_limits_guard = rate_limits.write().await;

        for (sub_id, subscription) in subscriptions_guard.iter() {
            // Filter notifications for this subscription
            let filtered_notifications: Vec<Notification> = notifications
                .iter()
                .filter(|n| subscription.should_receive(n))
                .cloned()
                .collect();

            if filtered_notifications.is_empty() {
                continue;
            }

            // Check rate limiting
            if let Some(rate_limit) = rate_limits_guard.get_mut(sub_id) {
                if !rate_limit.should_allow(config) {
                    log::debug!("Rate limit exceeded for batched subscription: {}", sub_id);
                    continue;
                }
            }

            // Send batch
            if let Some(sender) = senders_guard.get(sub_id) {
                let batch = NotificationBatch::new(filtered_notifications);
                if let Err(_) = sender.send(batch) {
                    log::debug!("Failed to send notification batch to subscription: {}", sub_id);
                }
            }
        }
    }

    fn start_cleanup_task(&self) {
        let subscriptions = self.subscriptions.clone();
        let senders = self.senders.clone();
        let batch_senders = self.batch_senders.clone();
        let rate_limits = self.rate_limits.clone();

        tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

            loop {
                cleanup_interval.tick().await;

                let now = Instant::now();
                let mut to_remove = Vec::new();

                // Find inactive subscriptions
                {
                    let subscriptions_guard = subscriptions.read().await;
                    for (sub_id, subscription) in subscriptions_guard.iter() {
                        // Remove subscriptions inactive for more than 1 hour
                        if now.duration_since(subscription.last_activity) > Duration::from_secs(3600) {
                            to_remove.push(*sub_id);
                        }
                    }
                }

                // Remove inactive subscriptions
                for sub_id in to_remove {
                    {
                        let mut subscriptions_guard = subscriptions.write().await;
                        subscriptions_guard.remove(&sub_id);
                    }
                    {
                        let mut senders_guard = senders.write().await;
                        senders_guard.remove(&sub_id);
                    }
                    {
                        let mut batch_senders_guard = batch_senders.write().await;
                        batch_senders_guard.remove(&sub_id);
                    }
                    {
                        let mut rate_limits_guard = rate_limits.write().await;
                        rate_limits_guard.remove(&sub_id);
                    }
                    
                    log::debug!("Cleaned up inactive subscription: {}", sub_id);
                }
            }
        });
    }
}

/// Statistics about the notification system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationStats {
    pub active_subscriptions: usize,
    pub buffered_notifications: usize,
    pub persisted_notifications: usize,
    pub total_published: u64,
}