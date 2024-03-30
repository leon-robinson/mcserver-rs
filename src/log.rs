#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        print!("[WARN] ");
        println!($($arg)*);
    })
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        print!("[INFO] ");
        println!($($arg)*);
    })
}

#[macro_export]
macro_rules! severe {
    ($($arg:tt)*) => ({
        print!("[SEVERE] ");
        println!($($arg)*);
    })
}
