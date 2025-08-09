//! BIP39 Mnemonic code for generating deterministic keys.

use crate::{GdkError, Result};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;

/// Number of bits in entropy for different mnemonic lengths
const ENTROPY_BITS_128: usize = 128; // 12 words
const ENTROPY_BITS_160: usize = 160; // 15 words  
const ENTROPY_BITS_192: usize = 192; // 18 words
const ENTROPY_BITS_224: usize = 224; // 21 words
const ENTROPY_BITS_256: usize = 256; // 24 words

/// Number of PBKDF2 iterations for mnemonic-to-seed conversion
const PBKDF2_ITERATIONS: u32 = 2048;

/// BIP39 word list for English
const ENGLISH_WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blow", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "care", "career", "careful",
    "careless", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "cast", "casual",
    "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
    "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change",
    "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry",
    "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk",
    "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clamp", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic",
    "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster",
    "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color",
    "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
    "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
    "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl",
    "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
    "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion",
    "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash",
    "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
    "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand",
    "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive",
    "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "device", "devote",
    "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity",
    "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss",
    "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog",
    "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove",
    "draft", "dragon", "drama", "drape", "draw", "dream", "dress", "drift", "drill", "drink",
    "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust",
    "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily",
    "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg",
    "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite",
    "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
    "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance",
    "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope",
    "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape",
    "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact",
    "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit",
    "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express",
    "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith",
    "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion",
    "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee",
    "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction",
    "field", "figure", "file", "fill", "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag",
    "flame", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower",
    "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food",
    "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster",
    "found", "fox", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost",
    "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget",
    "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
    "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle",
    "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give",
    "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove",
    "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
    "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great",
    "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess",
    "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster",
    "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
    "head", "health", "heart", "heavy", "hedgehog", "height", "held", "hello", "helmet", "help",
    "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby",
    "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn",
    "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human",
    "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid",
    "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image",
    "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income",
    "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit",
    "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect",
    "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron",
    "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous",
    "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice",
    "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key",
    "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
    "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady",
    "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava",
    "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture",
    "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard",
    "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light",
    "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard",
    "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery",
    "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury",
    "lying", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make",
    "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march",
    "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math",
    "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal",
    "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit",
    "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic",
    "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
    "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
    "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain",
    "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom",
    "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow",
    "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew",
    "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night",
    "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing",
    "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
    "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off",
    "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once",
    "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange",
    "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other",
    "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen",
    "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel",
    "panic", "panther", "paper", "parade", "parent", "park", "parrot", "part", "pass", "patch",
    "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear",
    "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person",
    "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig",
    "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place",
    "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem",
    "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion",
    "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise",
    "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print",
    "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project",
    "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull",
    "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse",
    "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quiet",
    "quilt", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
    "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare",
    "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild",
    "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
    "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind",
    "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require",
    "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion",
    "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge",
    "rifle", "right", "rigid", "ring", "riot", "ripple", "rise", "risk", "ritual", "rival",
    "river", "road", "roast", "rob", "robot", "robust", "rocket", "romance", "roof", "rookie",
    "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug",
    "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad",
    "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce",
    "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school",
    "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search",
    "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select",
    "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup",
    "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift",
    "shine", "ship", "shirt", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove",
    "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign",
    "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister",
    "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull",
    "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot",
    "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
    "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "sold",
    "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
    "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
    "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start",
    "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
    "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong",
    "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such",
    "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super",
    "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swear", "sweet", "swift", "swim", "swing", "switch", "sword",
    "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk",
    "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell",
    "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme",
    "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw",
    "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip",
    "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet",
    "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic",
    "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
    "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel",
    "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip",
    "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube",
    "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice",
    "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle",
    "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe",
    "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper",
    "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility",
    "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various",
    "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version",
    "very", "vessel", "veteran", "viable", "vibe", "vicious", "victory", "video", "view", "village",
    "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal",
    "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk",
    "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water",
    "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend",
    "weird", "welcome", "west", "wet", "what", "wheat", "wheel", "when", "where", "whip",
    "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing",
    "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
    "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck",
    "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth",
    "zebra", "zero", "zone", "zoo"
];

/// Supported languages for BIP39 mnemonics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    // Future: Japanese, French, Spanish, etc.
}

impl Language {
    /// Get the word list for this language
    pub fn wordlist(&self) -> &'static [&'static str] {
        match self {
            Language::English => ENGLISH_WORDLIST,
        }
    }
}

/// Represents a BIP39 mnemonic phrase
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mnemonic {
    words: Vec<String>,
    language: Language,
}

impl Mnemonic {
    /// Generate a new mnemonic with the specified entropy length
    pub fn generate(entropy_bits: usize) -> Result<Self> {
        Self::generate_with_language(entropy_bits, Language::English)
    }

    /// Generate a new mnemonic with specified entropy length and language
    pub fn generate_with_language(entropy_bits: usize, language: Language) -> Result<Self> {
        // Validate entropy length
        if ![ENTROPY_BITS_128, ENTROPY_BITS_160, ENTROPY_BITS_192, ENTROPY_BITS_224, ENTROPY_BITS_256].contains(&entropy_bits) {
            return Err(GdkError::InvalidInput(format!(
                "Invalid entropy length: {}. Must be one of: 128, 160, 192, 224, 256", 
                entropy_bits
            )));
        }

        // Generate random entropy
        let entropy_bytes = entropy_bits / 8;
        let mut entropy = vec![0u8; entropy_bytes];
        thread_rng().fill_bytes(&mut entropy);

        Self::from_entropy_with_language(&entropy, language)
    }

    /// Create a mnemonic from entropy bytes
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        Self::from_entropy_with_language(entropy, Language::English)
    }

    /// Create a mnemonic from entropy bytes with specified language
    pub fn from_entropy_with_language(entropy: &[u8], language: Language) -> Result<Self> {
        // Validate entropy length
        let entropy_bits = entropy.len() * 8;
        if ![ENTROPY_BITS_128, ENTROPY_BITS_160, ENTROPY_BITS_192, ENTROPY_BITS_224, ENTROPY_BITS_256].contains(&entropy_bits) {
            return Err(GdkError::InvalidInput(format!(
                "Invalid entropy length: {} bytes. Must be one of: 16, 20, 24, 28, 32 bytes", 
                entropy.len()
            )));
        }

        // Calculate checksum
        let hash = Sha256::digest(entropy);
        let checksum_bits = entropy_bits / 32;
        let checksum = hash[0] >> (8 - checksum_bits);

        // Combine entropy and checksum
        let mut combined = entropy.to_vec();
        combined.push(checksum);

        // Convert to 11-bit indices
        let word_count = (entropy_bits + checksum_bits) / 11;
        let mut indices = Vec::with_capacity(word_count);
        
        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;
        
        for &byte in &combined {
            bit_buffer = (bit_buffer << 8) | (byte as u32);
            bits_in_buffer += 8;
            
            while bits_in_buffer >= 11 {
                let index = (bit_buffer >> (bits_in_buffer - 11)) & 0x7FF;
                indices.push(index as usize);
                bits_in_buffer -= 11;
            }
        }

        // Convert indices to words
        let wordlist = language.wordlist();
        let words: Result<Vec<String>> = indices
            .into_iter()
            .map(|index| {
                if index >= wordlist.len() {
                    Err(GdkError::InvalidInput(format!("Invalid word index: {}", index)))
                } else {
                    Ok(wordlist[index].to_string())
                }
            })
            .collect();

        Ok(Mnemonic {
            words: words?,
            language,
        })
    }

    /// Parse a mnemonic from a string
    pub fn from_str(mnemonic_str: &str) -> Result<Self> {
        Self::from_str_with_language(mnemonic_str, Language::English)
    }

    /// Parse a mnemonic from a string with specified language
    pub fn from_str_with_language(mnemonic_str: &str, language: Language) -> Result<Self> {
        let words: Vec<String> = mnemonic_str
            .split_whitespace()
            .map(|s| s.to_lowercase())
            .collect();

        // Validate word count
        if ![12, 15, 18, 21, 24].contains(&words.len()) {
            return Err(GdkError::InvalidInput(format!(
                "Invalid mnemonic length: {} words. Must be 12, 15, 18, 21, or 24 words",
                words.len()
            )));
        }

        let mnemonic = Mnemonic { words, language };
        
        // Validate the mnemonic
        mnemonic.validate()?;
        
        Ok(mnemonic)
    }

    /// Validate the mnemonic checksum
    pub fn validate(&self) -> Result<()> {
        let wordlist = self.language.wordlist();
        
        // Convert words to indices
        let indices: Result<Vec<usize>> = self.words
            .iter()
            .map(|word| {
                wordlist
                    .iter()
                    .position(|&w| w == word)
                    .ok_or_else(|| GdkError::InvalidInput(format!("Invalid word: {}", word)))
            })
            .collect();
        let indices = indices?;

        // Convert indices to bits
        let total_bits = self.words.len() * 11;
        let entropy_bits = (total_bits * 32) / 33;
        let checksum_bits = total_bits - entropy_bits;

        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;
        let mut entropy_bytes = Vec::new();

        for &index in &indices {
            bit_buffer = (bit_buffer << 11) | (index as u32);
            bits_in_buffer += 11;

            while bits_in_buffer >= 8 && entropy_bytes.len() < entropy_bits / 8 {
                let byte = (bit_buffer >> (bits_in_buffer - 8)) & 0xFF;
                entropy_bytes.push(byte as u8);
                bits_in_buffer -= 8;
            }
        }

        // Extract checksum from remaining bits
        let checksum_mask = (1 << checksum_bits) - 1;
        let provided_checksum = (bit_buffer & checksum_mask) as u8;

        // Calculate expected checksum
        let hash = Sha256::digest(&entropy_bytes);
        let expected_checksum = hash[0] >> (8 - checksum_bits);

        if provided_checksum != expected_checksum {
            return Err(GdkError::InvalidInput("Invalid mnemonic checksum".to_string()));
        }

        Ok(())
    }

    /// Convert mnemonic to seed using PBKDF2
    pub fn to_seed(&self, passphrase: Option<&str>) -> Result<Seed> {
        let mnemonic_str = self.words.join(" ");
        let salt = format!("mnemonic{}", passphrase.unwrap_or(""));
        
        let mut seed = [0u8; 64];
        pbkdf2::<Hmac<Sha512>>(
            mnemonic_str.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ITERATIONS,
            &mut seed,
        );

        Ok(Seed(seed))
    }

    /// Get the words as a vector
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Get the language
    pub fn language(&self) -> Language {
        self.language
    }

    /// Get the entropy that generated this mnemonic
    pub fn to_entropy(&self) -> Result<Vec<u8>> {
        let wordlist = self.language.wordlist();
        
        // Convert words to indices
        let indices: Result<Vec<usize>> = self.words
            .iter()
            .map(|word| {
                wordlist
                    .iter()
                    .position(|&w| w == word)
                    .ok_or_else(|| GdkError::InvalidInput(format!("Invalid word: {}", word)))
            })
            .collect();
        let indices = indices?;

        // Convert indices to bits
        let total_bits = self.words.len() * 11;
        let entropy_bits = (total_bits * 32) / 33;

        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;
        let mut entropy_bytes = Vec::new();

        for &index in &indices {
            bit_buffer = (bit_buffer << 11) | (index as u32);
            bits_in_buffer += 11;

            while bits_in_buffer >= 8 && entropy_bytes.len() < entropy_bits / 8 {
                let byte = (bit_buffer >> (bits_in_buffer - 8)) & 0xFF;
                entropy_bytes.push(byte as u8);
                bits_in_buffer -= 8;
            }
        }

        Ok(entropy_bytes)
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.words.join(" "))
    }
}

/// Represents a BIP39 seed derived from a mnemonic
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed(pub [u8; 64]);

impl Seed {
    /// Get the seed bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Convert to a vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_mnemonic_generation_12_words() {
        let mnemonic = Mnemonic::generate(128).unwrap();
        assert_eq!(mnemonic.words().len(), 12);
        assert_eq!(mnemonic.language(), Language::English);
        
        // Validate the generated mnemonic
        mnemonic.validate().unwrap();
    }

    #[test]
    fn test_mnemonic_generation_24_words() {
        let mnemonic = Mnemonic::generate(256).unwrap();
        assert_eq!(mnemonic.words().len(), 24);
        assert_eq!(mnemonic.language(), Language::English);
        
        // Validate the generated mnemonic
        mnemonic.validate().unwrap();
    }

    #[test]
    fn test_mnemonic_from_entropy() {
        // BIP39 test vector 1
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        
        let expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(mnemonic.to_string(), expected);
        
        // Validate the mnemonic
        mnemonic.validate().unwrap();
    }

    #[test]
    fn test_mnemonic_from_entropy_24_words() {
        // BIP39 test vector with 256-bit entropy
        let entropy = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        
        let expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        assert_eq!(mnemonic.to_string(), expected);
        
        // Validate the mnemonic
        mnemonic.validate().unwrap();
    }

    #[test]
    fn test_mnemonic_from_str() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
        
        assert_eq!(mnemonic.words().len(), 12);
        assert_eq!(mnemonic.to_string(), mnemonic_str);
        
        // Should validate successfully
        mnemonic.validate().unwrap();
    }

    #[test]
    fn test_mnemonic_validation_invalid_checksum() {
        // Invalid mnemonic with wrong checksum
        let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = Mnemonic::from_str(invalid_mnemonic);
        
        assert!(result.is_err());
        if let Err(GdkError::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid mnemonic checksum"));
        } else {
            panic!("Expected InvalidInput error with checksum message");
        }
    }

    #[test]
    fn test_mnemonic_validation_invalid_word() {
        let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalidword";
        let result = Mnemonic::from_str(invalid_mnemonic);
        
        assert!(result.is_err());
        if let Err(GdkError::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid word: invalidword"));
        } else {
            panic!("Expected InvalidInput error with invalid word message");
        }
    }

    #[test]
    fn test_mnemonic_validation_invalid_length() {
        let invalid_mnemonic = "abandon abandon abandon abandon abandon";
        let result = Mnemonic::from_str(invalid_mnemonic);
        
        assert!(result.is_err());
        if let Err(GdkError::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid mnemonic length: 5 words"));
        } else {
            panic!("Expected InvalidInput error with length message");
        }
    }

    #[test]
    fn test_mnemonic_to_seed_no_passphrase() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
        let seed = mnemonic.to_seed(None).unwrap();
        
        // BIP39 test vector expected seed
        let expected_seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        assert_eq!(seed.as_bytes().to_vec(), expected_seed);
    }

    #[test]
    fn test_mnemonic_to_seed_with_passphrase() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
        let seed = mnemonic.to_seed(Some("TREZOR")).unwrap();
        
        // BIP39 test vector expected seed with passphrase
        let expected_seed = hex::decode("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap();
        assert_eq!(seed.as_bytes().to_vec(), expected_seed);
    }

    #[test]
    fn test_mnemonic_to_entropy_roundtrip() {
        let original_entropy = hex::decode("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c").unwrap();
        let mnemonic = Mnemonic::from_entropy(&original_entropy).unwrap();
        let recovered_entropy = mnemonic.to_entropy().unwrap();
        
        assert_eq!(original_entropy, recovered_entropy);
    }

    #[test]
    fn test_entropy_to_mnemonic_to_seed_roundtrip() {
        let entropy = hex::decode("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let seed = mnemonic.to_seed(None).unwrap();
        
        // Verify we can recreate the mnemonic from the same entropy
        let mnemonic2 = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.to_string(), mnemonic2.to_string());
        
        // Verify seeds are identical
        let seed2 = mnemonic2.to_seed(None).unwrap();
        assert_eq!(seed.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn test_invalid_entropy_lengths() {
        // Test various invalid entropy lengths
        let invalid_lengths = [15, 17, 19, 25, 31, 33]; // Invalid byte lengths
        
        for &len in &invalid_lengths {
            let entropy = vec![0u8; len];
            let result = Mnemonic::from_entropy(&entropy);
            assert!(result.is_err());
            
            if let Err(GdkError::InvalidInput(msg)) = result {
                assert!(msg.contains("Invalid entropy length"));
            } else {
                panic!("Expected InvalidInput error for entropy length {}", len);
            }
        }
    }

    #[test]
    fn test_invalid_entropy_bits_generation() {
        let invalid_bits = [64, 96, 129, 200, 300];
        
        for &bits in &invalid_bits {
            let result = Mnemonic::generate(bits);
            assert!(result.is_err());
            
            if let Err(GdkError::InvalidInput(msg)) = result {
                assert!(msg.contains("Invalid entropy length"));
            } else {
                panic!("Expected InvalidInput error for entropy bits {}", bits);
            }
        }
    }

    #[test]
    fn test_all_valid_mnemonic_lengths() {
        let test_cases = [
            (128, 12), // 128 bits -> 12 words
            (160, 15), // 160 bits -> 15 words
            (192, 18), // 192 bits -> 18 words
            (224, 21), // 224 bits -> 21 words
            (256, 24), // 256 bits -> 24 words
        ];
        
        for &(entropy_bits, expected_words) in &test_cases {
            let mnemonic = Mnemonic::generate(entropy_bits).unwrap();
            assert_eq!(mnemonic.words().len(), expected_words);
            mnemonic.validate().unwrap();
        }
    }

    #[test]
    fn test_case_insensitive_parsing() {
        let mnemonic_str = "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
        
        // Should normalize to lowercase
        assert_eq!(mnemonic.words()[0], "abandon");
        mnemonic.validate().unwrap();
    }

    #[test]
    fn test_whitespace_handling() {
        let mnemonic_str = "  abandon   abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
        
        assert_eq!(mnemonic.words().len(), 12);
        mnemonic.validate().unwrap();
    }

    #[test]
    fn test_language_wordlist() {
        let wordlist = Language::English.wordlist();
        assert_eq!(wordlist.len(), 2048);
        assert_eq!(wordlist[0], "abandon");
        assert_eq!(wordlist[2047], "zoo");
    }

    #[test]
    fn test_seed_methods() {
        let seed_bytes = [42u8; 64];
        let seed = Seed(seed_bytes);
        
        assert_eq!(seed.as_bytes(), &seed_bytes);
        assert_eq!(seed.to_vec(), seed_bytes.to_vec());
        assert_eq!(seed.as_ref(), &seed_bytes[..]);
    }

    #[test]
    fn test_multiple_entropy_sources() {
        // Test that different entropy produces different mnemonics
        let mnemonic1 = Mnemonic::generate(256).unwrap();
        let mnemonic2 = Mnemonic::generate(256).unwrap();
        
        // Should be extremely unlikely to be the same
        assert_ne!(mnemonic1.to_string(), mnemonic2.to_string());
        
        // Both should validate
        mnemonic1.validate().unwrap();
        mnemonic2.validate().unwrap();
    }

    #[test]
    fn test_bip39_test_vectors() {
        // Additional BIP39 test vectors
        let test_vectors = [
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow"
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
            ),
        ];

        for (entropy_hex, expected_mnemonic) in test_vectors.iter() {
            let entropy = hex::decode(entropy_hex).unwrap();
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(mnemonic.to_string(), *expected_mnemonic);
            mnemonic.validate().unwrap();
        }
    }
}