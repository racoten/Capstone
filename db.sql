CREATE TABLE `cpu` (
  `id` int NOT NULL AUTO_INCREMENT,
  `architecture` varchar(50) NOT NULL,
  `victim_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `victim_id` (`victim_id`),
  CONSTRAINT `cpu_ibfk_1` FOREIGN KEY (`victim_id`) REFERENCES `victim` (`id`)
);

CREATE TABLE `gpu` (
  `id` int NOT NULL AUTO_INCREMENT,
  `information` varchar(50) NOT NULL,
  `victim_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `victim_id` (`victim_id`),
  CONSTRAINT `gpu_ibfk_1` FOREIGN KEY (`victim_id`) REFERENCES `victim` (`id`)
);

CREATE TABLE `network` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(50) NOT NULL,
  `mac_address` varchar(50) NOT NULL,
  `victim_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `victim_id` (`victim_id`),
  CONSTRAINT `network_ibfk_1` FOREIGN KEY (`victim_id`) REFERENCES `victim` (`id`)
);

CREATE TABLE `operating_system` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `victim_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `victim_id` (`victim_id`),
  CONSTRAINT `operating_system_ibfk_1` FOREIGN KEY (`victim_id`) REFERENCES `victim` (`id`)
);

CREATE TABLE `operator` (
  `id` int NOT NULL AUTO_INCREMENT,
  `operator_name` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `operator_login` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `date_registered` date NOT NULL,
  `first_name` varchar(100) NOT NULL,
  `last_name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `phone_number` varchar(20) NOT NULL,
  `operator_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `operator_id` (`operator_id`),
  CONSTRAINT `operator_login_ibfk_1` FOREIGN KEY (`operator_id`) REFERENCES `operator` (`id`)
);

CREATE TABLE `ram` (
  `id` int NOT NULL AUTO_INCREMENT,
  `amount` int NOT NULL,
  `victim_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `victim_id` (`victim_id`),
  CONSTRAINT `ram_ibfk_1` FOREIGN KEY (`victim_id`) REFERENCES `victim` (`id`)
);

CREATE TABLE `storage` (
  `id` int NOT NULL AUTO_INCREMENT,
  `amount` int NOT NULL,
  `victim_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `victim_id` (`victim_id`),
  CONSTRAINT `storage_ibfk_1` FOREIGN KEY (`victim_id`) REFERENCES `victim` (`id`)
);

CREATE TABLE `victim` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `operator_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `operator_id` (`operator_id`),
  CONSTRAINT `victim_ibfk_1` FOREIGN KEY (`operator_id`) REFERENCES `operator` (`id`)
);
