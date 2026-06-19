//! Ephemeris CLI — `eph` binary entry point.
//!
//! Features: encrypt, decrypt, repudiate, info, genkey, genpass.
//! Supports base64 armor output and secure file shredding.

mod args;

use anyhow::{bail, Context, Result};
use args::{Argon2Options, Command, PasswordOptions};
use clap::Parser;
use ephemeris_core::*;
use rand::RngCore;
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use zeroize::Zeroize;

// ASCII armor markers
const ARMOR_HEADER: &str = "-----BEGIN EPHEMERIS-----";
const ARMOR_FOOTER: &str = "-----END EPHEMERIS-----";

// Diceware word list (EFF short list, 1296 words ≈ 10.3 bits/word)
const DICEWARE: &[&str] = &[
    "acid","acorn","acre","acts","afar","afloat","afoot","after","age","agent",
    "agile","aging","agony","ahead","aide","aids","aim","air","alarm","alias",
    "alien","alike","alive","aloe","alone","aloud","amber","ample","angel",
    "anger","angle","ankle","apple","april","aqua","area","arena","argue",
    "arise","arm","armor","army","aroma","arrow","arson","art","ashen","aside",
    "ask","atom","attic","audio","autumn","awake","award","awoke","axis","bacon",
    "badge","bagel","baggy","baked","baker","balmy","banjo","barge","barn",
    "bash","basil","bask","batch","bath","baton","bats","blade","blank","blast",
    "blaze","blend","bless","blimp","blink","bloat","blob","blog","blot","blown",
    "blue","blunt","blurt","boast","boat","body","bolt","bonk","bonus","bony",
    "book","booth","boots","boss","both","bound","bowl","box","boy","brain",
    "brand","brave","bread","break","breed","bribe","brick","bride","brief",
    "bring","broad","broil","brood","brook","brown","brush","buddy","bug",
    "bulb","bulge","bulk","bully","bump","bunny","burn","burnt","burst","bus",
    "bust","busy","but","cabin","cage","cake","calf","call","calm","came",
    "camp","cane","cape","card","care","cargo","case","cash","cast","cave",
    "cell","cent","chant","chaos","charm","chase","cheek","cheer","chef","chess",
    "chest","chief","child","chill","chip","chirp","choke","chop","chunk",
    "cinch","circa","cite","city","clad","claim","clamp","clan","clash","clasp",
    "class","claw","clay","clean","clear","cleat","cleft","clerk","click",
    "cling","clip","cloak","clock","clone","close","cloth","cloud","clover",
    "club","cluck","clue","clump","coach","coal","coast","code","coil","coin",
    "colt","comb","come","comic","comma","cone","cook","cool","cope","copy",
    "cord","core","cork","corn","cost","cot","couch","cough","could","count",
    "court","cove","cover","cow","crab","craft","cramp","crane","crash","crate",
    "crave","crawl","crazy","cream","credit","crest","crew","crime","crisp",
    "cross","crowd","crown","crumb","crush","crust","cub","cult","cup","curb",
    "cure","curl","curry","curve","cut","cyber","cycle","dad","daily","dance",
    "dart","dash","data","date","dawn","day","dead","deaf","deal","dear",
    "debit","deck","decor","deed","delay","denim","dense","dent","depot",
    "depth","derby","desk","dial","diary","dice","dig","dill","dime","dimly",
    "diner","dirty","disco","ditch","ditto","dive","dock","dodge","doing",
    "dolphin","dome","done","donor","door","doubt","dove","down","dozen",
    "draft","drag","drain","drama","drank","draw","dress","dried","drift",
    "drill","drive","drone","drool","drop","drove","drown","drum","dry",
    "duck","dug","dull","dumb","dump","dust","duty","dye","eager","eagle",
    "ear","earth","ease","east","easy","eat","edge","edgy","eel","egg",
    "eh","elbow","elder","elect","elf","elite","elk","elm","ember","empty",
    "end","enemy","enjoy","enter","epic","era","evade","even","event","ever",
    "evil","exam","exile","exist","extra","fable","face","fact","fade","fail",
    "faint","fair","fairy","faith","fake","fall","false","fame","family",
    "fancy","fang","far","farm","fast","fat","fate","fawn","fear","feast",
    "fed","fee","feed","feel","felt","fence","fern","fetch","fever","few",
    "field","fiery","fifth","fifty","fig","fight","file","fill","film","final",
    "finch","find","fine","fire","firm","first","fish","fit","five","fix",
    "flag","flail","flair","flake","flame","flap","flash","flask","fled",
    "flesh","flick","flight","fling","flint","flip","flirt","float","flock",
    "flood","floor","flora","floss","flour","flow","flu","fluff","fluid",
    "fluke","flush","flute","flux","fly","foam","focus","fog","foil","fold",
    "folk","follow","food","foot","force","forest","forget","fork","form",
    "fort","found","fox","foyer","frail","frame","frank","fraud","fray","free",
    "freight","fresh","frog","from","front","frost","frown","frozen","fruit",
    "fuel","full","fume","fun","fund","fur","fuse","fuss","future","gag",
    "gain","gala","game","gap","gas","gate","gave","gaze","gear","gecko",
    "geek","gel","gem","genre","gift","gig","gills","girl","give","glad",
    "glance","glare","glass","glee","glide","globe","gloom","glory","gloss",
    "glove","glow","glue","gnat","gnaw","goal","goat","going","gold","gone",
    "good","goofy","gore","grab","grace","grade","grain","grand","grant",
    "grape","graph","grasp","grass","grave","gravy","gray","great","greed",
    "green","greet","grief","grill","grin","grip","grit","groom","grow",
    "grunt","guide","gulf","gum","gun","gush","gut","guy","gym","habit",
    "had","hail","hair","half","hall","ham","happy","hard","harm","has",
    "hat","hate","haul","haunt","have","hazel","head","heap","hear","heat",
    "heavy","hedge","heel","height","held","helmet","help","hen","her","here",
    "hero","hid","high","hill","hint","hip","hire","hiss","hit","hive","hold",
    "hole","home","hood","hoof","hook","hope","horn","horse","hose","host",
    "hot","hour","house","hover","how","huge","hull","human","humor","hung",
    "hunt","hurry","hurt","hut","ice","icon","idea","idle","igloo","image",
    "imp","inch","index","info","ink","inner","input","insect","into","iron",
    "isle","issue","item","ivory","jack","jam","jar","jaw","jazz","jeans",
    "jeep","jelly","jet","jewel","job","jockey","join","joke","jolly","joy",
    "judge","jug","juice","jump","jungle","jury","just","kale","keep","kettle",
    "key","kick","kid","killer","kin","kind","king","kiss","kit","kite",
    "knee","knelt","knife","knit","knob","knock","knot","know","koala","lab",
    "lace","lack","lady","lake","lamb","lame","lamp","land","lane","lap",
    "large","lash","last","late","laugh","lava","law","lawn","lay","lazy",
    "lead","leaf","leak","lean","leap","left","leg","lemon","lend","length",
    "lens","less","let","lever","lid","life","lift","light","like","limb",
    "limit","limp","line","linen","link","lint","lion","lip","list","lit",
    "live","load","loan","lobe","lock","lodge","loft","log","lone","long",
    "look","loop","loose","lord","loss","lost","lot","loud","love","low",
    "loyal","luck","lump","lunch","lung","lure","lurk","macho","mad","maid",
    "mail","main","major","make","male","mall","mango","man","many","map",
    "march","mark","mask","mass","mast","mat","match","mate","math","max",
    "may","meal","mean","medal","meet","melon","melt","men","menu","meow",
    "mercy","mesh","mess","metal","meter","might","mild","mile","milk","mill",
    "mimic","min","minnow","mint","minus","miser","miss","mist","mister",
    "mitt","mix","moan","mob","mocha","mock","mode","model","mom","moral",
    "more","moss","most","motor","mound","mount","mouse","mouth","move",
    "movie","much","muck","mug","mulch","mule","mull","mush","music","must",
    "muzzle","myth","nail","name","nap","near","neat","neck","need","nerve",
    "nest","net","new","next","nice","nick","niece","nine","no","noble",
    "nod","noise","none","nook","noon","nor","norm","north","nose","not",
    "note","notice","noun","now","nudge","nuke","null","numb","nut","oak",
    "oasis","oat","ocean","odd","ode","odor","off","often","oil","old",
    "olive","omen","onion","only","ooze","open","opt","orange","orbit",
    "order","organ","other","otter","ought","our","out","output","oval",
    "oven","over","owl","own","pace","pack","pad","page","paid","pail",
    "pain","paint","pair","pal","palm","pan","panel","pants","paper","park",
    "part","pass","past","pat","patch","path","patio","pause","pave","pay",
    "peace","peak","peanut","pear","pearl","pedal","peel","peer","pellet",
    "pen","pencil","penguin","penny","perch","perk","pet","phone","photo",
    "piano","pick","pie","pig","pike","pile","pill","pin","pine","pink",
    "pipe","pit","pitch","pizza","place","plain","plan","plane","plant",
    "plate","play","plea","plow","pluck","plug","plus","pocket","poem",
    "poet","point","poke","pole","poll","pond","pony","pool","poor","pop",
    "porch","port","pose","post","pot","pound","pour","power","press",
    "price","pride","prime","print","prism","prize","probe","prom","prop",
    "prose","proud","prove","pry","ps","pub","puff","pull","pulp","puma",
    "pump","punk","punt","pup","pure","purr","push","put","quack","quake",
    "quart","queen","quick","quiet","quill","quilt","quit","quiz","quote",
    "race","rack","radar","radio","raft","rag","rage","raid","rail","rain",
    "raise","rally","ramp","ranch","range","rank","rant","rapid","rash",
    "rat","rate","rave","raw","ray","razor","reach","read","real","reap",
    "rear","reason","rebel","recap","red","reef","reel","refer","rein",
    "relax","rely","rent","repay","reset","rest","retro","ribbon","rice",
    "rich","ride","right","rim","ring","riot","rip","rise","risk","river",
    "roam","roar","roast","robe","rock","rode","rod","roll","roof","room",
    "root","rope","rose","rot","rotate","rough","round","route","row","royal",
    "rub","rude","rug","rule","rum","run","rush","rust","rut","sack","sad",
    "safe","sail","salad","salmon","salt","same","sand","sang","sank","sap",
    "sat","save","saw","say","scale","scan","scar","scene","scent","school",
    "scoop","scope","score","scout","scrap","sea","seal","seam","search",
    "season","seat","second","see","seed","self","sell","send","sense",
    "serve","set","seven","shack","shade","shadow","shaft","shake","shall",
    "sham","shape","share","shark","sharp","shawl","she","sheep","sheet",
    "shelf","shell","shift","ship","shirt","shock","shoe","shone","shook",
    "shoot","shop","shore","short","shot","shout","shove","show","shrimp",
    "shrink","shy","sick","side","sift","sigh","sight","sign","silent","silk",
    "silly","silo","simple","since","sing","sink","sip","sir","sit","site",
    "six","size","ski","skill","skin","skirt","skull","sky","slab","slack",
    "slam","slang","slant","slap","slash","slate","slave","sled","sleep",
    "sleet","slept","slice","slick","slimy","slip","slit","slob","slot",
    "slug","slum","slurp","smack","small","smart","smell","smile","smirk",
    "smith","smog","snack","snag","snail","snake","snap","snarl","sneak",
    "sniff","snore","snout","snow","snug","soak","soap","soccer","social",
    "sock","soda","soft","solar","sold","some","song","soon","sore","sorry",
    "sort","soul","sound","soup","sour","south","space","spade","spark",
    "speak","spear","speed","spell","spend","spent","spice","spider","spike",
    "spill","spin","spine","spirit","spit","splash","spoil","spoke","sponge",
    "spoon","sport","spot","spray","spread","spring","spur","spy","square",
    "squash","stack","staff","stage","stair","stake","stale","stamp","stand",
    "star","stare","state","stay","steak","steal","steam","steel","steep",
    "steer","stem","step","stew","stick","still","sting","stir","stock",
    "stole","stomp","stone","stood","stool","stop","store","storm","story",
    "stout","stove","straw","stray","strip","struck","strut","stub","stuck",
    "stud","stuff","stump","stun","stunt","style","such","sudden","sue","sugar",
    "suit","summer","sun","super","sure","surf","swamp","swan","swap","sway",
    "swear","sweat","sweep","sweet","swept","swift","swim","swing","switch",
    "sword","swore","symbol","syrup","table","tack","tag","tail","take","tale",
    "talk","tall","tank","tap","tape","target","task","taste","tax","teach",
    "team","tear","tech","teen","teeth","tell","ten","tennis","tent","term",
    "test","text","thank","that","them","then","these","they","thick","thief",
    "thin","thing","think","third","this","thorn","those","thread","three",
    "threw","thrill","thrive","throat","throne","through","throw","thud",
    "thumb","thus","ticket","tide","tidy","tie","tight","tile","till","time",
    "tiny","tire","toast","today","toe","token","told","tomato","tomorrow",
    "ton","tone","tongue","tonight","too","took","tool","top","torch","toss",
    "total","touch","toward","tower","town","toy","trace","track","trade",
    "trail","train","trait","trap","trash","tray","treat","tree","trek",
    "trend","trial","tribe","trick","tried","trim","trio","trip","troll",
    "trot","trout","truck","true","truly","trump","trunk","trust","truth",
    "try","tub","tug","tulip","tuna","tune","turf","turn","turtle","tutor",
    "twice","twin","twist","two","tying","type","ugly","uncle","under","undo",
    "unfair","unfold","unify","unique","unit","unite","unity","unreal","unrest",
    "unripe","unsafe","until","unzip","up","upon","upper","upset","urban",
    "urge","us","use","used","user","utter","valley","value","van","vapor",
    "vary","vase","vast","vegan","veil","verb","very","vest","veto","vice",
    "view","villa","vine","visa","vision","visit","visor","vocal","voice",
    "void","volt","vote","vowel","voyage","wacky","wade","wage","waist",
    "wait","wake","walk","wall","walnut","waltz","wand","want","war","ward",
    "warm","warn","warp","wart","wash","wasp","waste","watch","water","wave",
    "wax","way","weak","weapon","wear","weave","web","wed","wedge","week",
    "weep","weigh","weird","well","went","were","west","wet","whack","whale",
    "what","wheat","wheel","when","where","which","whiff","while","whine",
    "whip","whirl","whisk","white","who","whole","why","wick","wide","wife",
    "wig","wild","will","win","wind","wine","wing","wink","wipe","wire",
    "wise","wish","with","woke","wolf","woman","won","wonder","wood","wool",
    "word","wore","work","world","worry","worse","worst","worth","would",
    "wrap","wrist","write","wrong","wrote","yak","yam","yard","yarn","yawn",
    "year","yell","yet","yoga","yolk","young","zebra","zero","zinc","zombie",
    "zone",
];

fn main() -> Result<()> {
    let cli = args::Cli::parse();
    match cli.command {
        Command::Encrypt(a) => cmd_encrypt(a),
        Command::Decrypt(a) => cmd_decrypt(a),
        Command::Repudiate(a) => cmd_repudiate(a),
        Command::Info(a) => cmd_info(a),
        Command::GenKey(a) => cmd_genkey(a),
        Command::GenPass(a) => cmd_genpass(a),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_password_confirm(opts: &PasswordOptions, prompt: &str) -> Result<Vec<u8>> {
    // If password provided via flag/file, use directly (no confirm)
    if let Some(ref pw) = opts.password {
        return Ok(pw.as_bytes().to_vec());
    }
    if let Some(ref path) = opts.password_file {
        let s = fs::read_to_string(path)
            .with_context(|| format!("failed to read password file: {path}"))?;
        return Ok(s.as_bytes().to_vec());
    }
    // Interactive with confirmation
    let pw = rpassword::prompt_password(prompt)?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if pw != confirm {
        bail!("passwords do not match");
    }
    if pw.is_empty() {
        eprintln!("⚠ Warning: empty password!");
    }
    Ok(pw.into_bytes())
}

fn make_params(opts: &Argon2Options) -> Argon2Params {
    Argon2Params {
        time_cost: opts.time_cost,
        memory_cost: opts.memory_cost,
        parallelism: opts.parallelism,
    }
}

fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).context("failed to read stdin")?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("failed to read: {path}"))
    }
}

fn write_output(path: &str, data: &[u8], force: bool) -> Result<()> {
    if path == "-" {
        let mut handle = io::stdout().lock();
        handle.write_all(data).context("failed to write stdout")?;
        handle.flush().context("failed to flush stdout")?;
        return Ok(());
    }
    if !force && Path::new(path).exists() {
        bail!("output '{}' already exists. Use --force to overwrite.", path);
    }
    fs::write(path, data).with_context(|| format!("failed to write: {path}"))
}

/// Armor: wrap binary data in base64 with header/footer.
fn armor_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let b64 = base64_encode(data);
    let mut out = String::with_capacity(ARMOR_HEADER.len() + b64.len() + ARMOR_FOOTER.len() + 3);
    writeln!(out, "{}", ARMOR_HEADER).unwrap();
    // Wrap at 64 chars
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    writeln!(out, "{}", ARMOR_FOOTER).unwrap();
    out
}

/// De-armor: extract base64 data between header and footer.
fn armor_decode(text: &str) -> Result<Vec<u8>> {
    let start = text.find(ARMOR_HEADER).context("missing armor header")?;
    let body_start = start + ARMOR_HEADER.len();
    let end = text[body_start..].find(ARMOR_FOOTER).context("missing armor footer")?;
    let body = &text[body_start..body_start + end];
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode(&b64)
}

/// Simple base64 encode (no external crate needed).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Simple base64 decode.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let input = input.trim();
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in input.bytes() {
        if c == b'=' { break; }
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        } as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Securely erase a file: overwrite 3x with random, then delete.
fn shred_file(path: &str) -> Result<()> {
    let meta = fs::metadata(path)
        .with_context(|| format!("cannot stat file for shred: {path}"))?;
    let size = meta.len() as usize;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("cannot open file for shred: {path}"))?;

    // 3 passes of random data
    for _pass in 0..3 {
        let mut written = 0usize;
        f.seek(std::io::SeekFrom::Start(0))?;
        while written < size {
            let chunk_size = (size - written).min(65536);
            let mut buf = vec![0u8; chunk_size];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            f.write_all(&buf)?;
            written += chunk_size;
        }
        f.flush()?;
    }
    drop(f);

    // Truncate to zero before delete
    let f = fs::OpenOptions::new().write(true).truncate(true).open(path)?;
    drop(f);
    fs::remove_file(path).with_context(|| format!("failed to delete: {path}"))?;
    Ok(())
}

/// Format bytes as human-readable size.
fn human_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn cmd_encrypt(a: args::EncryptArgs) -> Result<()> {
    let plaintext = read_input(&a.input)?;
    let plen = plaintext.len();
    let mut password = read_password_confirm(&a.password, "Encryption password: ")?;
    let params = make_params(&a.argon2);

    eprintln!("Encrypting {}...", human_size(plen));
    let result = encrypt(&plaintext, &password, &params);
    password.zeroize();

    let output_data = if a.armor || a.output == "-" {
        armor_encode(&result.eph_file).into_bytes()
    } else {
        result.eph_file.clone()
    };

    write_output(&a.output, &output_data, a.force)?;

    if a.armor {
        eprintln!("✓ Encrypted {} → '{}' (armored, {} chars)",
            human_size(plen), a.output, output_data.len());
    } else {
        eprintln!("✓ Encrypted {} → '{}' (.eph, {})",
            human_size(plen), a.output, human_size(result.eph_file.len()));
    }

    if let Some(ref key_path) = a.key_file {
        write_output(key_path, &result.key_file, a.force)?;
        eprintln!("✓ Key file → '{}'", key_path);
    }

    if a.shred && a.input != "-" {
        eprintln!("Shredding original file...");
        shred_file(&a.input)?;
        eprintln!("✓ Original file securely erased");
    }

    Ok(())
}

fn cmd_decrypt(a: args::DecryptArgs) -> Result<()> {
    let raw = read_input(&a.input)?;

    let eph_data = if a.armor {
        let text = String::from_utf8(raw)
            .context("armored input must be valid UTF-8 text")?;
        armor_decode(&text)?
    } else {
        // Auto-detect: try armor if data starts with '-'
        if raw.starts_with(b"-----BEGIN EPHEMERIS-----") {
            let text = String::from_utf8(raw)
                .context("armored input must be valid UTF-8 text")?;
            armor_decode(&text)?
        } else {
            raw
        }
    };

    let mut password = read_password_confirm(&a.password, "Decryption password: ")?;
    let params = make_params(&a.argon2);

    let _parsed = parse_eph(&eph_data).context("invalid .eph file")?;
    let plaintext = decrypt(&eph_data, &password, &params)
        .context("failed to decrypt")?;
    password.zeroize();

    write_output(&a.output, &plaintext, a.force)?;
    eprintln!("✓ Decrypted {} → '{}'", human_size(plaintext.len()), a.output);
    Ok(())
}

fn cmd_repudiate(a: args::RepudiateArgs) -> Result<()> {
    let eph_data = read_input(&a.input)?;
    let fake_plaintext = read_input(&a.fake_plaintext)?;
    let mut password = read_password_confirm(&a.password, "Fake (cover story) password: ")?;
    let params = make_params(&a.argon2);

    let parsed = parse_eph(&eph_data).context("invalid .eph file")?;

    if fake_plaintext.len() != parsed.ciphertext.len() {
        bail!(
            "length mismatch: fake message is {} bytes, original is {} bytes.\n\
             Hint: the fake message must be exactly the same length.",
            fake_plaintext.len(),
            parsed.ciphertext.len()
        );
    }

    let new_eph = repudiate_eph(&eph_data, &fake_plaintext, &password, &params)
        .context("failed to repudiate")?;
    password.zeroize();

    let output_data = if a.armor {
        armor_encode(&new_eph).into_bytes()
    } else {
        new_eph.clone()
    };

    write_output(&a.output, &output_data, a.force)?;
    eprintln!("✓ Repudiated → '{}'", a.output);
    eprintln!("⚠ Original message is now UNRECOVERABLE from this file.");
    Ok(())
}

fn cmd_info(a: args::InfoArgs) -> Result<()> {
    let data = read_input(&a.file)?;

    // Auto-detect armor
    let data = if data.starts_with(b"-----BEGIN EPHEMERIS-----") {
        let text = String::from_utf8(data).context("invalid UTF-8 in armor")?;
        armor_decode(&text)?
    } else {
        data
    };

    if let Ok(parsed) = parse_eph(&data) {
        println!("File type:       .eph (Ephemeris combined)");
        println!("File size:       {} ({})", data.len(), human_size(data.len()));
        println!("Mode:            OTP (one-time pad)");
        println!("Salt:            {}", hex::encode(parsed.salt));
        println!("Message length:  {} bytes ({})", parsed.ciphertext.len(), human_size(parsed.ciphertext.len()));
        println!("Key blob:        {} bytes", parsed.key_blob.len());
        println!("Overhead:        {} bytes ({} header + {} key)", 25 + parsed.key_blob.len(), 25, human_size(parsed.key_blob.len()));
        let ratio = if parsed.ciphertext.len() > 0 {
            (data.len() as f64 / parsed.ciphertext.len() as f64 * 100.0) as usize
        } else { 0 };
        println!("Expansion:       {}% (OTP: 200% = 1:1 key + 1:1 ct)", ratio);
        return Ok(());
    }

    if let Ok((salt, key_blob)) = parse_key(&data) {
        println!("File type:       .key (Ephemeris standalone key)");
        println!("File size:       {} ({})", data.len(), human_size(data.len()));
        println!("Mode:            OTP (one-time pad)");
        println!("Salt:            {}", hex::encode(salt));
        println!("Key blob:        {} bytes ({})", key_blob.len(), human_size(key_blob.len()));
        println!("Message length:  {} bytes (same as key blob in OTP mode)", key_blob.len());
        return Ok(());
    }

    bail!("not a valid .eph or .key file (bad magic or corrupted)");
}

fn cmd_genkey(a: args::GenKeyArgs) -> Result<()> {
    let raw_key = read_input(&a.key_input)?;
    let mut password = read_password_confirm(&a.password, "Password for key file: ")?;
    let params = make_params(&a.argon2);

    if raw_key.is_empty() {
        eprintln!("⚠ Warning: empty key → empty .key file.");
    }

    let salt = generate_salt();
    let key_blob = wrap_key(&raw_key, &password, &salt, &params)
        .map_err(|e| anyhow::anyhow!("failed to wrap key: {e}"))?;
    password.zeroize();

    let key_file = build_key(&salt, &key_blob);
    write_output(&a.output, &key_file, a.force)?;
    eprintln!("✓ Key file → '{}' ({} key → {} total)",
        a.output, human_size(raw_key.len()), human_size(key_file.len()));
    Ok(())
}

fn cmd_genpass(a: args::GenPassArgs) -> Result<()> {
    let n = a.words.max(1).min(20);
    let mut words = Vec::with_capacity(n);
    for _ in 0..n {
        let mut idx = [0u8; 2];
        rand::rngs::OsRng.fill_bytes(&mut idx);
        let i = (u16::from_le_bytes(idx) as usize) % DICEWARE.len();
        words.push(DICEWARE[i]);
    }

    let password = words.join("-");
    println!("{}", password);

    if a.show_entropy {
        let bits = (n as f64) * (DICEWARE.len() as f64).log2();
        eprintln!("Entropy: ~{:.0} bits ({} words × {:.1} bits/word)",
            bits, n, (DICEWARE.len() as f64).log2());
    }
    Ok(())
}
