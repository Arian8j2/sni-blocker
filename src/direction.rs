use std::fmt::Display;

// could probably wrap pcap::Direction instead, but in that case
// clap wouldn't be able to create a good help page for it
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum Direction {
    In,
    Out,
    InOut,
}

impl Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::In => "in",
            Self::Out => "out",
            Self::InOut => "inout",
        };
        write!(f, "{str}")
    }
}

impl From<Direction> for pcap::Direction {
    fn from(value: Direction) -> Self {
        match value {
            Direction::In => pcap::Direction::In,
            Direction::Out => pcap::Direction::Out,
            Direction::InOut => pcap::Direction::InOut,
        }
    }
}
