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

CREATE TABLE arpdata_old LIKE arpdata;

CREATE TABLE devicedata(
  hw_address        CHAR(17) NOT NULL,
  vendor            VARCHAR(256),
  PRIMARY KEY (hw_address)
);

CREATE TABLE vlandata(
  vlan              SMALLINT NOT NULL,
  network_location  VARCHAR(256) NOT NULL,
  network_function  VARCHAR(256) NOT NULL,
  PRIMARY KEY (vlan)
);

CREATE TABLE daemondata (
  hostname          VARCHAR(256) NOT NULL,
  iface             VARCHAR(256) NOT NULL,
  last_updated      DATETIME,
  last_notified     DATETIME,
  PRIMARY KEY (hostname, iface)
);

CREATE TABLE epicsdata(
  hw_address        CHAR(17) NOT NULL,
  vlan              SMALLINT NOT NULL,
  pv_name           VARCHAR(256) NOT NULL,
  last_seen         DATETIME,
  PRIMARY KEY (hw_address, vlan, pv_name)
);

CREATE TABLE registrationdata(
  hw_address        CHAR(17) NOT NULL,
  not_registered    BOOL DEFAULT false,
  registered_by     VARCHAR(256),
  notes             TEXT,
  created           DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated           DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (hw_address)
);

