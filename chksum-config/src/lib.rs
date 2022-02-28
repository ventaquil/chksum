/// Contains informations about hashing process.
///
/// # Examples
///
/// ```rust
/// use chksum_config::Config;
///
/// let config = Config::default();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub chunk_size: usize,
    pub with_paths: bool,
}

impl Config {
    pub const DEFAULT_CHUNK_SIZE: usize = 65536;
    pub const DEFAULT_WITH_PATHS: bool = false;

    /// Constructs new config with given parameters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_config::Config;
    ///
    /// let config = Config::new(32, false);
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    #[must_use]
    pub const fn new(chunk_size: usize, with_paths: bool) -> Self {
        Self { chunk_size, with_paths }
    }
}

impl AsRef<Config> for Config {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn as_ref(&self) -> &Config {
        self
    }
}

impl Default for Config {
    /// Creates config with default parameters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_config::Config;
    ///
    /// let config = Config::default();
    /// assert_eq!(
    ///     config,
    ///     Config::new(Config::DEFAULT_CHUNK_SIZE, Config::DEFAULT_WITH_PATHS)
    /// );
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn default() -> Self {
        let chunk_size = Self::DEFAULT_CHUNK_SIZE;
        let with_paths = Self::DEFAULT_WITH_PATHS;
        Self::new(chunk_size, with_paths)
    }
}

impl From<(usize, bool)> for Config {
    /// Converts tuple into `Config`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_config::Config;
    ///
    /// let config = (Config::DEFAULT_CHUNK_SIZE, Config::DEFAULT_WITH_PATHS);
    /// let config = Config::from(config);
    /// assert_eq!(
    ///     config,
    ///     Config::new(Config::DEFAULT_CHUNK_SIZE, Config::DEFAULT_WITH_PATHS)
    /// );
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(config: (usize, bool)) -> Self {
        let (chunk_size, with_paths) = config;
        Self::new(chunk_size, with_paths)
    }
}

impl From<Config> for (usize, bool) {
    /// Converts `Config` into tuple.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_config::Config;
    ///
    /// let config = Config::default();
    /// let (chunk_size, with_paths) = config.into();
    /// assert_eq!(
    ///     (chunk_size, with_paths),
    ///     (Config::DEFAULT_CHUNK_SIZE, Config::DEFAULT_WITH_PATHS)
    /// );
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(config: Config) -> Self {
        (config.chunk_size, config.with_paths)
    }
}
