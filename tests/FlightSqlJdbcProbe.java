// Drives a Flight SQL endpoint through Arrow's flight-sql-jdbc-driver and
// prints "key<TAB>value" facts for flight_sql_client_conformance.py.
// Usage: java -cp flight-sql-jdbc-driver.jar FlightSqlJdbcProbe.java <port> <query> <table> [opt...]
// Options: "tls" connects with grpc+tls (certificate verification off: test
// certificates are self-signed); "update=<sql>" and "prepared_update=<sql>"
// report Statement.executeUpdate / PreparedStatement.executeUpdate (twice);
// "java_client" drives the echo server through Arrow's Java FlightSqlClient;
// "bind_long=<sql>" / "bind_string=<sql>" prepare <sql>, bind its one `?`
// with setLong(4) / setString("o'k") and report the parameter type, the
// described column count and the result.
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.flight.FlightClient;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.flight.FlightInfo;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.flight.FlightStream;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.flight.Location;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.flight.sql.FlightSqlClient;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.memory.BufferAllocator;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.memory.RootAllocator;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.vector.BigIntVector;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.vector.VarCharVector;
import org.apache.arrow.driver.jdbc.shaded.org.apache.arrow.vector.VectorSchemaRoot;

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

    // Every row of a FlightInfo's stream, columns joined by ',' rows by ';'.
    static String stream(FlightSqlClient sql, FlightInfo info, String... cols) throws Exception {
        List<String> out = new ArrayList<>();
        try (FlightStream st = sql.getStream(info.getEndpoints().get(0).getTicket())) {
            for (int guard = 0; guard < 100000 && st.next(); ++guard) {
                VectorSchemaRoot r = st.getRoot();
                for (int i = 0; i < r.getRowCount(); ++i) {
                    List<String> row = new ArrayList<>();
                    for (String c : cols) row.add(String.valueOf(r.getVector(c).getObject(i)));
                    out.add(String.join(",", row));
                }
            }
        }
        return String.join(";", out);
    }

    // Arrow's own Java FlightSqlClient: GetXdbcTypeInfo, and parameters bound
    // through DoPut (it follows DoPutPreparedStatementResult's new handle).
    static void javaClient(int port) throws Exception {
        try (BufferAllocator a = new RootAllocator();
             FlightClient fc = FlightClient.builder(a, Location.forGrpcInsecure("127.0.0.1", port)).build()) {
            FlightSqlClient sql = new FlightSqlClient(fc);
            fact("java_type_info", stream(sql, sql.getXdbcTypeInfo(), "type_name", "data_type"));
            try (FlightSqlClient.PreparedStatement ps = sql.prepare("SELECT ?");
                 BigIntVector v = new BigIntVector("p", a)) {
                fact("java_param_fields", String.valueOf(ps.getParameterSchema().getFields().size()));
                v.allocateNew(1);
                v.set(0, 4);
                v.setValueCount(1);
                try (VectorSchemaRoot root = VectorSchemaRoot.of(v)) {
                    ps.setParameters(root);
                    fact("java_bound", stream(sql, ps.execute(), "id", "name"));
                    ps.clearParameters();
                }
            }
            try (FlightSqlClient.PreparedStatement ps = sql.prepare("ECHO ?");
                 VarCharVector v = new VarCharVector("s", a)) {
                v.allocateNew(1);
                v.setSafe(0, "o'k".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                v.setValueCount(1);
                try (VectorSchemaRoot root = VectorSchemaRoot.of(v)) {
                    ps.setParameters(root);
                    fact("java_echo", stream(sql, ps.execute(), "sql"));
                    ps.clearParameters();
                }
            }
            try (FlightSqlClient.PreparedStatement ps = sql.prepare("UPSERT ?");
                 BigIntVector v = new BigIntVector("n", a)) {
                v.allocateNew(2);
                v.set(0, 2);
                v.set(1, 3);
                v.setValueCount(2);
                try (VectorSchemaRoot root = VectorSchemaRoot.of(v)) {
                    ps.setParameters(root);
                    fact("java_update", String.valueOf(ps.executeUpdate()));
                    ps.clearParameters();
                }
            }
            fact("java_statement_update", String.valueOf(sql.executeUpdate("UPSERT 6")));
        }
    }

    // PreparedStatement.setLong/setString through the advertised
    // parameter_schema; a failure is reported as the fact's value.
    static void bind(Connection c, String key, String sql, Object v) {
        try (PreparedStatement p = c.prepareStatement(sql)) {
            java.sql.ParameterMetaData params = p.getParameterMetaData();
            fact(key + "_param_type",
                 params.getParameterCount() > 0 ? params.getParameterTypeName(1) : "");
            java.sql.ResultSetMetaData cols = p.getMetaData();
            fact(key + "_result_cols", cols == null ? "none" : String.valueOf(cols.getColumnCount()));
            if (v instanceof Long) p.setLong(1, (Long) v);
            else p.setString(1, (String) v);
            fact(key, table(p.executeQuery()));
        } catch (Exception e) {
            fact(key, "error: " + String.valueOf(e.getMessage()).replace('\n', ' '));
        }
    }

    public static void main(String[] args) throws Exception {
        boolean tls = false;
        boolean javaClient = false;
        String update = null;
        String preparedUpdate = null;
        String bindLong = null;
        String bindString = null;
        for (int i = 3; i < args.length; ++i) {
            if (args[i].equals("tls")) tls = true;
            else if (args[i].equals("java_client")) javaClient = true;
            else if (args[i].startsWith("update=")) update = args[i].substring(7);
            else if (args[i].startsWith("prepared_update=")) preparedUpdate = args[i].substring(16);
            else if (args[i].startsWith("bind_long=")) bindLong = args[i].substring(10);
            else if (args[i].startsWith("bind_string=")) bindString = args[i].substring(12);
        }
        String url = "jdbc:arrow-flight-sql://127.0.0.1:" + args[0] + (tls
                ? "/?useEncryption=true&disableCertificateVerification=true"
                : "/?useEncryption=false");
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
            if (update != null) {
                try (Statement s = c.createStatement()) {
                    fact("update", String.valueOf(s.executeUpdate(update)));
                }
            }
            if (preparedUpdate != null) {
                try (PreparedStatement p = c.prepareStatement(preparedUpdate)) {
                    fact("prepared_update", p.executeUpdate() + "," + p.executeUpdate());
                }
            }
            if (bindLong != null) bind(c, "bind_long", bindLong, 4L);
            if (bindString != null) bind(c, "bind_string", bindString, "o'k");
            try (Statement s = c.createStatement()) {
                s.executeQuery("FAIL jdbc");
                fact("error", "none");
            } catch (SQLException e) {
                fact("error", String.valueOf(e.getMessage()).replace('\n', ' '));
            }
        }
        if (javaClient) javaClient(Integer.parseInt(args[0]));
        fact("done", "ok");
    }
}
