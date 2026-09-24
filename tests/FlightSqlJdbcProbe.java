// Drives a Flight SQL endpoint through Arrow's flight-sql-jdbc-driver and
// prints "key<TAB>value" facts for flight_sql_client_conformance.py.
// Usage: java -cp flight-sql-jdbc-driver.jar FlightSqlJdbcProbe.java <port> <query> <table>
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class FlightSqlJdbcProbe {
    static void fact(String k, String v) {
        System.out.println(k + "\t" + v);
    }

    static String rows(ResultSet rs, int... cols) throws SQLException {
        List<String> out = new ArrayList<>();
        for (int guard = 0; guard < 100000 && rs.next(); ++guard) {
            List<String> r = new ArrayList<>();
            for (int c : cols) r.add(rs.getString(c));
            out.add(String.join(",", r));
        }
        rs.close();
        return String.join(";", out);
    }

    static String table(ResultSet rs) throws SQLException {
        int n = rs.getMetaData().getColumnCount();
        int[] cols = new int[n];
        List<String> head = new ArrayList<>();
        for (int i = 0; i < n; ++i) {
            cols[i] = i + 1;
            head.add(rs.getMetaData().getColumnLabel(i + 1));
        }
        String body = rows(rs, cols);
        return String.join(",", head) + (body.isEmpty() ? "" : ";" + body);
    }

    public static void main(String[] args) throws Exception {
        String url = "jdbc:arrow-flight-sql://127.0.0.1:" + args[0] + "/?useEncryption=false";
        String query = args[1];
        String tbl = args[2];
        try (Connection c = DriverManager.getConnection(url)) {
            DatabaseMetaData md = c.getMetaData();
            fact("product", md.getDatabaseProductName());
            fact("version", md.getDatabaseProductVersion());
            fact("read_only", String.valueOf(md.isReadOnly()));
            fact("table_types", rows(md.getTableTypes(), 1));
            fact("catalogs", rows(md.getCatalogs(), 1));
            fact("schemas", rows(md.getSchemas(), 1));
            fact("tables", rows(md.getTables(null, null, "%", null), 3, 4));
            fact("columns", rows(md.getColumns(null, null, tbl, "%"), 4, 6));
            fact("primary_keys", rows(md.getPrimaryKeys(null, null, tbl), 4, 5));
            fact("imported_keys", rows(md.getImportedKeys(null, null, tbl), 8));
            try (Statement s = c.createStatement()) {
                fact("statement", table(s.executeQuery(query)));
            }
            try (PreparedStatement p = c.prepareStatement(query)) {
                fact("prepared_1", table(p.executeQuery()));
                fact("prepared_2", table(p.executeQuery()));
            }
            try (Statement s = c.createStatement()) {
                s.executeQuery("FAIL jdbc");
                fact("error", "none");
            } catch (SQLException e) {
                fact("error", String.valueOf(e.getMessage()).replace('\n', ' '));
            }
        }
        fact("done", "ok");
    }
}
