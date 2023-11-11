CREATE TABLE Users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    email VARCHAR(100),
    role ENUM('Admin', 'User') NOT NULL,
    created_at TIMESTAMP DEFAULT current_timestamp
);

CREATE TABLE Sites (
    site_id SERIAL PRIMARY KEY,
    description TEXT
);

CREATE TABLE Breakers (
    breaker_id SERIAL PRIMARY KEY,
    site_id INT REFERENCES Sites(site_id),
    description TEXT
);

CREATE TABLE Batteries (
    battery_id SERIAL PRIMARY KEY,
    site_id INT REFERENCES Sites(site_id),
    description TEXT
);

CREATE TABLE BreakerSwitchEvents (
    event_id SERIAL PRIMARY KEY,
    breaker_id INT REFERENCES Breakers(breaker_id),
    switch_time TIMESTAMP,
    source ENUM ('LUMA', 'Solar'),
    monitor_id INT
);

CREATE TABLE BreakerConsumption (
    consumption_id SERIAL PRIMARY KEY,
    breaker_id INT REFERENCES Breakers(breaker_id),
    timestamp TIMESTAMP,
    consumption_luma FLOAT,
    consumption_solar FLOAT,
    monitor_id INT
);

CREATE TABLE BlackoutEvents (
    event_id SERIAL PRIMARY KEY,
    site_id INT REFERENCES Sites(site_id),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    monitor_id INT
);

CREATE TABLE BatteryStatus (
    status_id SERIAL PRIMARY KEY,
    battery_id INT REFERENCES Batteries(battery_id),
    timestamp TIMESTAMP,
    voltage FLOAT,
    monitor_id INT
);

CREATE TABLE LumaVoltage (
    record_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    voltage FLOAT,
    monitor_id INT
);

CREATE TABLE UserMonitoring (
    monitor_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES Users(user_id),
    battery_status_id INT REFERENCES BatteryStatus(status_id),
    breaker_switch_event_id INT REFERENCES BreakerSwitchEvents(event_id),
    breaker_consumption_id INT REFERENCES BreakerConsumption(consumption_id),
    blackout_event_id INT REFERENCES BlackoutEvents(event_id),
    luma_voltage_id INT REFERENCES LumaVoltage(record_id)
);