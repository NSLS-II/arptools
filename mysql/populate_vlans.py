from nsls2network import nsls2network as nsls2network


def write_sql():
    print("""
USE arptools;
DROP TABLE IF EXISTS vlandata;
CREATE TABLE vlandata(
    vlan              SMALLINT NOT NULL,
    network_location  VARCHAR(256) NOT NULL,
    network_function  VARCHAR(256) NOT NULL,
    PRIMARY KEY (vlan)
);
    """)

    for loc,nets in nsls2network.items():
        for type, net in nets.items():
            print("INSERT INTO vlandata (vlan, network_location, network_function)");
            print(f"VALUES ({net['vlan']}, '{loc}', '{type.upper()}');")

if __name__ == "__main__":
    write_sql()
