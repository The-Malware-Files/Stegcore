// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

//! Rotating NLT Bible verses. Shared between GUI and CLI.

pub struct Verse {
    pub text: &'static str,
    pub reference: &'static str,
}

pub const VERSES: &[Verse] = &[
    Verse { text: "For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.", reference: "John 3:16" },
    Verse { text: "I can do everything through Christ, who gives me strength.", reference: "Philippians 4:13" },
    Verse { text: "Trust in the Lord with all your heart; do not depend on your own understanding. Seek his will in all you do, and he will show you which path to take.", reference: "Proverbs 3:5-6" },
    Verse { text: "The Lord is my shepherd; I have all that I need.", reference: "Psalm 23:1" },
    Verse { text: "And we know that God causes everything to work together for the good of those who love God and are called according to his purpose for them.", reference: "Romans 8:28" },
    Verse { text: "For I know the plans I have for you, says the Lord. They are plans for good and not for disaster, to give you a future and a hope.", reference: "Jeremiah 29:11" },
    Verse { text: "Don\u{2019}t be afraid, for I am with you. Don\u{2019}t be discouraged, for I am your God. I will strengthen you and help you. I will hold you up with my victorious right hand.", reference: "Isaiah 41:10" },
    Verse { text: "Jesus told him, \u{201c}I am the way, the truth, and the life. No one can come to the Father except through me.\u{201d}", reference: "John 14:6" },
    Verse { text: "Even when I walk through the darkest valley, I will not be afraid, for you are close beside me. Your rod and your staff protect and comfort me.", reference: "Psalm 23:4" },
    Verse { text: "But those who trust in the Lord will find new strength. They will soar high on wings like eagles. They will run and not grow weary. They will walk and not faint.", reference: "Isaiah 40:31" },
    Verse { text: "This is my command\u{2014}be strong and courageous! Do not be afraid or discouraged. For the Lord your God is with you wherever you go.", reference: "Joshua 1:9" },
    Verse { text: "For nothing will be impossible with God.", reference: "Luke 1:37" },
    Verse { text: "Come to me, all of you who are weary and carry heavy burdens, and I will give you rest.", reference: "Matthew 11:28" },
    Verse { text: "The Lord himself will fight for you. Just stay calm.", reference: "Exodus 14:14" },
    Verse { text: "Give all your worries and cares to God, for he cares about you.", reference: "1 Peter 5:7" },
    Verse { text: "Don\u{2019}t worry about anything; instead, pray about everything. Tell God what you need, and thank him for all he has done.", reference: "Philippians 4:6" },
    Verse { text: "The Lord is my light and my salvation\u{2014}so why should I be afraid? The Lord is my fortress, protecting me from danger, so why should I tremble?", reference: "Psalm 27:1" },
    Verse { text: "Love is patient and kind. Love is not jealous or boastful or proud or rude.", reference: "1 Corinthians 13:4-5" },
    Verse { text: "But seek first the Kingdom of God and his righteousness, and all these things will be given to you as well.", reference: "Matthew 6:33" },
    Verse { text: "For the word of God is alive and powerful. It is sharper than the sharpest two-edged sword.", reference: "Hebrews 4:12" },
    Verse { text: "No, despite all these things, overwhelming victory is ours through Christ, who loved us.", reference: "Romans 8:37" },
    Verse { text: "So now there is no condemnation for those who belong to Christ Jesus.", reference: "Romans 8:1" },
    Verse { text: "What is impossible for people is possible with God.", reference: "Luke 18:27" },
    Verse { text: "I am leaving you with a gift\u{2014}peace of mind and heart. And the peace I give is a gift the world cannot give. So don\u{2019}t be troubled or afraid.", reference: "John 14:27" },
    Verse { text: "The Lord bless you and keep you. The Lord smile on you and be gracious to you. The Lord show you his favour and give you his peace.", reference: "Numbers 6:24-26" },
    Verse { text: "Your word is a lamp to guide my feet and a light for my path.", reference: "Psalm 119:105" },
    Verse { text: "Yet I still dare to hope when I remember this: The faithful love of the Lord never ends! His mercies never cease.", reference: "Lamentations 3:21-22" },
    Verse { text: "Look! I stand at the door and knock. If you hear my voice and open the door, I will come in, and we will share a meal together as friends.", reference: "Revelation 3:20" },
    Verse { text: "For God has not given us a spirit of fear and timidity, but of power, love, and self-discipline.", reference: "2 Timothy 1:7" },
    Verse { text: "And let the peace that comes from Christ rule in your hearts. For as members of one body you are called to live in peace. And always be thankful.", reference: "Colossians 3:15" },
];

/// Get a verse based on current time (rotates every 10 minutes).
pub fn current_verse() -> &'static Verse {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let idx = ((secs / 600) as usize) % VERSES.len(); // 600s = 10 minutes
    &VERSES[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verses_not_empty() {
        assert!(!VERSES.is_empty());
    }

    #[test]
    fn all_verses_have_text_and_reference() {
        for v in VERSES {
            assert!(!v.text.is_empty(), "Verse text is empty");
            assert!(!v.reference.is_empty(), "Verse reference is empty");
        }
    }

    #[test]
    fn current_verse_returns_valid_verse() {
        let v = current_verse();
        assert!(!v.text.is_empty());
        assert!(!v.reference.is_empty());
    }

    #[test]
    fn verse_count() {
        // We have 30 verses
        assert!(VERSES.len() >= 25);
    }
}
