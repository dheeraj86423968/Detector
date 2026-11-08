"""argv: database name, sample dir. Create the sample database in the research postgres from the sample COPY files
(schema = the PIDSMaker dump's) and add the timestamp index the replay queries use."""
import sys
import psycopg2
db, d = sys.argv[1], sys.argv[2]
assert db.endswith("_sample")
c = psycopg2.connect(dbname="postgres", host="postgres", user="postgres", password="postgres"); c.autocommit = True
c.cursor().execute(f"DROP DATABASE IF EXISTS {db}"); c.cursor().execute(f"CREATE DATABASE {db}")
x = psycopg2.connect(dbname=db, host="postgres", user="postgres", password="postgres"); cur = x.cursor()
cur.execute("""CREATE TABLE event_table (src_node varchar, src_index_id varchar, operation varchar, dst_node varchar,
  dst_index_id varchar, event_uuid varchar NOT NULL, timestamp_rec bigint, _id bigint NOT NULL);
CREATE TABLE file_node_table (node_uuid varchar NOT NULL, hash_id varchar NOT NULL, path varchar, index_id bigint);
CREATE TABLE netflow_node_table (node_uuid varchar NOT NULL, hash_id varchar NOT NULL, src_addr varchar, src_port varchar,
  dst_addr varchar, dst_port varchar, index_id bigint);
CREATE TABLE subject_node_table (node_uuid varchar NOT NULL, hash_id varchar NOT NULL, path varchar, cmd varchar, index_id bigint);""")
for t, f in (("event_table", "events.copy"), ("subject_node_table", "subject_node_table.copy"),
             ("file_node_table", "file_node_table.copy"), ("netflow_node_table", "netflow_node_table.copy")):
    cur.copy_expert(f"COPY {t} FROM STDIN", open(f"{d}/{f}", "rb"))
    cur.execute(f"SELECT count(*) FROM {t}"); print(t, cur.fetchone()[0], flush=True)
cur.execute("CREATE INDEX ON event_table (timestamp_rec)")
x.commit()
