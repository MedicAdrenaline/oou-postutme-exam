-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    otp VARCHAR(6),  -- Changed to VARCHAR for OTP
    pin_attempts INT DEFAULT 0, -- Number of incorrect PIN attempts
    last_attempt_time DATETIME DEFAULT NULL, -- Last time an attempt was made
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Create pins table
CREATE TABLE pins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    pin_code VARCHAR(10) NOT NULL UNIQUE,  -- Pin code as VARCHAR
    exam_mode VARCHAR(50), -- JAMB, WAEC, etc.
    is_used BOOLEAN DEFAULT FALSE,
    device_id VARCHAR(255), -- For future security tracking
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT FALSE,  -- Correct this line to use valid SQL syntax
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create scores table
CREATE TABLE scores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    exam_mode VARCHAR(50), -- JAMB, WAEC, etc.
    subject VARCHAR(50), -- Biology, Chemistry, etc.
    score INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create questions table
CREATE TABLE questions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    exam_mode VARCHAR(50), -- JAMB, WAEC, etc.
    subject VARCHAR(50),
    question TEXT,
    option_a VARCHAR(255),
    option_b VARCHAR(255),
    option_c VARCHAR(255),
    option_d VARCHAR(255),
    correct_option CHAR(1) -- Correct answer: A, B, C, or D
);