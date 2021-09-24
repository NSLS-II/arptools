# Move old records to old database

INSERT INTO arpdata_old SELECT * FROM arpdata WHERE DATE(last_seen) < DATE_SUB(CURDATE(), INTERVAL 5 DAY);
DELETE FROM arpdata WHERE DATE(last_seen) < DATE_SUB(CURDATE(), INTERVAL 5 DAY);
