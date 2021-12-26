# TODO: why page numbers-1? 0 excluded as special?

# [
#   12556,
#   12557,
#   12558
# ]

def sqlite3_btree_walk($page):
  ( . as $root
  | ( def _t:
        if .type == "table_interior" or .type == "index_interior" then
          ($root.pages[.cells[].left_child-1, .right_pointer-1] | _t)
        elif .type == "table_leaf" or .type == "index_leaf" then
          .cells[]
        else
          error("unknown page type \(.type)")
        end;
      ($page | _t)
    )
  );

# CREATE TABLE sqlite_schema(
# 	type text,
# 	name text,
# 	tbl_name text,
# 	rootpage integer,
# 	sql text
# );
def sqlite3_schema:
  ( [ sqlite3_btree_walk(.pages[0])
    | .payload.contents as [$type, $name, $tbl_name, $rootpage, $sql]
    | { key: $name,
        value: {$type, $name, $tbl_name, $rootpage, $sql}
      }
    ]
  | from_entries
  );

def sqlite3_rows($name):
  ( sqlite3_schema[$name] as $s
  | if $s == null then error("could not find name") end
  | sqlite3_btree_walk(.pages[$s.rootpage-1])
  | . as {rowid: $rowid, payload: {$contents}}
  | $contents
  | tovalue
  | if .[0] == null then .[0] = $rowid end
  );

def _sqlite3_torepr:
  ( . as $root
  | sqlite3_schema
  | map(
      ( select(.type == "table") as $t
      | { key: $t.name,
          value: [$root | sqlite3_rows($t.name)]
        }
      )
    )
  | from_entries
  );
