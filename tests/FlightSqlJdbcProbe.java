// Drives a Flight SQL endpoint through Apache Arrow's Flight SQL JDBC driver
// and prints what JDBC reports, one "key<TAB>value" line per fact, for
// flight_sql_client_conformance.py to judge. Run as a single-file program:
//   java --add-opens=java.base/java.nio=ALL-UNNAMED -cp <flight-sql-jdbc-driver.jar> \
//        FlightSqlJdbcProbe.java <port> <query> <table>
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class FlightSqlJdbcProbe {
    static void out(String k, Object v) {
        System.out.println(k + "\t" + v);
    }

    static String rows(ResultSet rs, String... cols) throws Exception {
        List<String> all = new ArrayList<>();
        while (rs.next()) {
            List<String> r = new ArrayList<>();
            for (String c : cols) r.add(String.valueOf(rs.getObject(c)));
            all.add(String.join(",", r));
        }
        rs.close();
        return String.join(";", all);
    }

    static String grid(ResultSet rs) throws Exception {
        ResultSetMetaData md = rs.getMetaData();
        List<String> all = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (int c = 1; c <= md.getColumnCount(); ++c) names.add(md.getColumnLabel(c));
        all.add(String.join(",", names));
        while (rs.next()) {
            List<String> r = new ArrayList<>();
            for (int c = 1; c <= md.getColumnCount(); ++c) r.add(String.valueOf(rs.getObject(c)));
            all.add(String.join(",", r));
        }
        rs.close();
        return String.join(";", all);
    }

    public static void main(String[] args) throws Exception {
        String url = "jdbc:arrow-flight-sql://127.0.0.1:" + args[0] + "/?useEncryption=false";
        String query = args[1];
        String table = args[2];
        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseMetaData md = conn.getMetaData();
            out("product", md.getDatabaseProductName());
            out("version", md.getDatabaseProductVersion());
            out("read_only", md.isReadOnly());
            out("table_types", rows(md.getTableTypes(), "TABLE_TYPE"));
            out("catalogs", rows(md.getCatalogs(), "TABLE_CAT"));
            out("schemas", rows(md.getSchemas(), "TABLE_SCHEM"));
            out("tables", rows(md.getTables(null, null, "%", null), "TABLE_NAME", "TABLE_TYPE"));
            out("columns", rows(md.getColumns(null, null, table, "%"), "COLUMN_NAME", "TYPE_NAME"));
            out("primary_keys", rows(md.getPrimaryKeys(null, null, table), "COLUMN_NAME", "KEY_SEQ"));
            out("imported_keys", rows(md.getImportedKeys(null, null, table), "PKTABLE_NAME"));
            try (Statement st = conn.createStatement()) {
                out("statement", grid(st.executeQuery(query)));
            }
            try (PreparedStatement ps = conn.prepareStatement(query)) {
                out("prepared_1", grid(ps.executeQuery()));
                out("prepared_2", grid(ps.executeQuery()));
            }
            try (Statement st = conn.createStatement()) {
                st.executeQuery("FAIL jdbc");
                out("error", "none");
            } catch (Exception e) {
                out("error", e.getMessage().replace('\n', ' '));
            }
        }
        out("done", "ok");
    }
}
