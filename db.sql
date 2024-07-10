DROP DATABASE aef;
CREATE DATABASE aef;
  
USE `aef`;

CREATE TABLE `operator` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `operator_name` VARCHAR(50) NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `Operator_Login` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(100) NOT NULL,
    `password` VARCHAR(100) NOT NULL,
    `date_registered` DATE NOT NULL,
    `first_name` VARCHAR(100) NOT NULL,
    `last_name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `phone_number` VARCHAR(20) NOT NULL,
    `operator_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`operator_id`) REFERENCES `operator`(`id`)
);

CREATE TABLE `Victim` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(50) NOT NULL,
    `operator_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`operator_id`) REFERENCES `operator`(`id`)
);

CREATE TABLE `CPU` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `architecture` VARCHAR(50) NOT NULL,
    `victim_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`victim_id`) REFERENCES `Victim`(`id`)
);

CREATE TABLE `GPU` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `information` VARCHAR(50) NOT NULL,
    `victim_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`victim_id`) REFERENCES `Victim`(`id`)
);

CREATE TABLE `RAM` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `amount` INT NOT NULL,
    `victim_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`victim_id`) REFERENCES `Victim`(`id`)
);

CREATE TABLE `Storage` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `amount` INT NOT NULL,
    `victim_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`victim_id`) REFERENCES `Victim`(`id`)
);

CREATE TABLE `Operating_System` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(50) NOT NULL,
    `victim_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`victim_id`) REFERENCES `Victim`(`id`)
);

CREATE TABLE `Network` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `ip_address` VARCHAR(50) NOT NULL,
    `mac_address` VARCHAR(50) NOT NULL,
    `victim_id` INT NOT NULL,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`victim_id`) REFERENCES `Victim`(`id`)
);

-- insert operator
INSERT INTO operator (operator_name)VALUES ('John Doe');
INSERT INTO operator (operator_name) VALUES ('Jane Doe');
INSERT INTO operator (operator_name) VALUES ('Bob Johnson');

-- insert operator login
INSERT INTO Operator_Login (username, password, date_registered, first_name, last_name, email, phone_number, operator_id) VALUES ('operatorAdmin', 'ef92b778bafe771e89245b89', '2022-01-01', 'John', 'Doe', 'johndoe@example.com', '1234567890', 1);

-- insert operator login
INSERT INTO Operator_Login (username, password, date_registered, first_name, last_name, email, phone_number, operator_id) VALUES ('operatorUser1', 'af45b889e8b778bafe771e8924', '2022-01-02', 'Jane', 'Smith', 'janesmith@example.com', '0987654321', 2);

-- insert operator login
INSERT INTO Operator_Login (username, password, date_registered, first_name, last_name, email, phone_number, operator_id) VALUES ('operatorUser2', 'bf2c66c06659911881f383d447', '2022-01-03', 'Bob', 'Johnson', 'bobjohnson@example.com', '9876543210', 3);

  
-- insert victim
INSERT INTO Victim (username, operator_id)
VALUES ('steve.harrington', 1);
  
-- insert CPU
INSERT INTO CPU (architecture, victim_id)
VALUES ('x86_64', 1);
  
-- insert GPU
INSERT INTO GPU (information, victim_id)
VALUES ('Nvidia GTX 1050', 1);
  
-- insert RAM
INSERT INTO RAM (amount, victim_id)
VALUES (8, 1);
  
-- insert Storage
INSERT INTO Storage (amount, victim_id)
VALUES (256, 1);
  
-- insert Operating System
INSERT INTO Operating_System (name, victim_id)
VALUES ('Windows 10', 1);
  
-- insert Network
INSERT INTO Network (ip_address, mac_address, victim_id)
VALUES ('127.0.0.1', '00:11:22:33:44:55', 1);
  
-- insert victim 2
INSERT INTO Victim (username, operator_id)
VALUES ('nancy.wheeler', 1);
  
-- insert CPU for victim 2
INSERT INTO CPU (architecture, victim_id)
VALUES ('x86_64', 2);
  
-- insert GPU for victim 2
INSERT INTO GPU (information, victim_id)
VALUES ('AMD Radeon RX 5700', 2);
  
-- insert RAM for victim 2
INSERT INTO RAM (amount, victim_id)
VALUES (16, 2);
  
-- insert Storage for victim 2
INSERT INTO Storage (amount, victim_id)
VALUES (512, 2);
  
-- insert Operating System for victim 2
INSERT INTO Operating_System (name, victim_id)
VALUES ('Ubuntu 20.04 LTS', 2);
  
-- insert Network for victim 2
INSERT INTO Network (ip_address, mac_address, victim_id)
VALUES ('192.168.1.100', '12:34:56:78:90:ab', 2);

-- Get All Victims

SELECT Victim.username, Network.ip_address, Operating_System.name, CPU.architecture, GPU.information, RAM.amount, Storage.amount FROM Victim JOIN Network ON Victim.id = Network.victim_id JOIN Operating_System ON Victim.id = Operating_System.victim_id JOIN CPU ON Victim.id = CPU.victim_id JOIN GPU ON Victim.id = GPU.victim_id JOIN RAM ON Victim.id = RAM.victim_id JOIN Storage ON Victim.id = Storage.victim_id;

