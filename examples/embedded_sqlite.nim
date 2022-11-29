#====================================================================
#
#              Memlib - Load Windows DLL from memory
#                 (c) Copyright 2021-2022 Ward
#
#====================================================================

import sqlite/db_sqlite, math

let db = open(":memory:", "", "", "")

db.exec(sql"DROP TABLE IF EXISTS my_table")
db.exec(sql"""CREATE TABLE my_table (
                 id    INTEGER PRIMARY KEY,
                 name  VARCHAR(50) NOT NULL,
                 i     INT(11),
                 f     DECIMAL(18, 10)
              )""")

db.exec(sql"BEGIN")
for i in 1..1000:
  db.exec(sql"INSERT INTO my_table (name, i, f) VALUES (?, ?, ?)",
          "Item#" & $i, i, sqrt(i.float))
db.exec(sql"COMMIT")

for x in db.fastRows(sql"SELECT * FROM my_table"):
  echo x

let id = db.tryInsertId(sql"""INSERT INTO my_table (name, i, f)
                              VALUES (?, ?, ?)""",
                        "Item#1001", 1001, sqrt(1001.0))
echo "Inserted item: ", db.getValue(sql"SELECT name FROM my_table WHERE id=?", id)

db.close()
