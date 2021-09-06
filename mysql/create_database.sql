DROP DATABASE IF EXISTS arptools;
CREATE DATABASE arptools;
USE arptools;

CREATE TABLE arpdata(
  hw_address        CHAR(17) NOT NULL,
  vlan              SMALLINT NOT NULL,
  location          VARCHAR(256) NOT NULL,
  label             VARCHAR(256),
  ip_address        CHAR(15),
  hostname          VARCHAR(256),
  type              SMALLINT UNSIGNED DEFAULT 0,
  last_seen         DATETIME,
  created           DATETIME DEFAULT CURRENT_TIMESTAMP,
  registered        BOOL DEFAULT false,
  notified          DATETIME,
  block_notified    DATETIME,
  audited           DATETIME,
  dhcp_name         VARCHAR(256),
  visible           BOOL DEFAULT TRUE,
  PRIMARY KEY (hw_address, vlan, location)
);

CREATE TABLE devicedata(
  hw_address        CHAR(17) NOT NULL,
  vendor            VARCHAR(256),
  PRIMARY KEY (hw_address)
);
