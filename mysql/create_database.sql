DROP DATABASE IF EXISTS arptools;
CREATE DATABASE arptools;
USE arptools;

CREATE TABLE arpdata(
  hw_address CHAR(17) NOT NULL,
  ip_address CHAR(15),
  hostname   VARCHAR(256),
  location   VARCHAR(256) NOT NULL,
  label      VARCHAR(256) NOT NULL,
  last_seen  DATETIME,
  created    DATETIME DEFAULT CURRENT_TIMESTAMP,
  registered BOOL DEFAULT false NOT NULL,
  PRIMARY KEY (hw_address)
);
