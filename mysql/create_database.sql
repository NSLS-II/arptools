DROP DATABASE IF EXISTS arptools;
CREATE DATABASE arptools;
USE arptools;

CREATE TABLE arpdata(
  hw_address        CHAR(17) NOT NULL,
  ip_address        CHAR(15),
  hostname          VARCHAR(256),
  location          VARCHAR(256) NOT NULL,
  label             VARCHAR(256) NOT NULL,
  last_seen         DATETIME,
  created           DATETIME DEFAULT CURRENT_TIMESTAMP,
  registered        BOOL DEFAULT false,
  last_notified     DATETIME,
  last_audited      DATETIME,
  type_arp          BOOL DEFAULT false,
  type_udp          BOOL DEFAULT false,
  type_dhcp         BOOL DEFAULT false,
  dhcp_name         VARCHAR(256),
  visible           BOOL DEFAULT true,
  PRIMARY KEY (hw_address)
);
