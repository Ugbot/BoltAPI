// boltapi/auth/smtp_client gtest — helpers + mailer interface.
// Live network paths (real SMTP) are exercised in the gestalt integration tests.

#include <gtest/gtest.h>
#include <cstring>

#include "boltapi/auth/smtp_client.h"

using namespace bolt::api::auth::smtp;

TEST(SmtpHelpers, EmailValidation) {
    EXPECT_TRUE (is_plausible_email("a@b.c"));
    EXPECT_TRUE (is_plausible_email("alice.smith+tag@example.co.uk"));
    EXPECT_FALSE(is_plausible_email(""));
    EXPECT_FALSE(is_plausible_email("no-at-sign"));
    EXPECT_FALSE(is_plausible_email("@no-local"));
    EXPECT_FALSE(is_plausible_email("no-domain@"));
    EXPECT_FALSE(is_plausible_email("two@@signs"));
    EXPECT_FALSE(is_plausible_email("with space@x"));
    EXPECT_FALSE(is_plausible_email("with<bracket@x"));
}

TEST(SmtpHelpers, AuthPlainEncoding) {
    // RFC 4616: \0 user \0 pass -> base64
    EXPECT_EQ(build_auth_plain("alice", "secret"), "AGFsaWNlAHNlY3JldA==");
    EXPECT_EQ(build_auth_plain("", ""), "AAA=");
}

TEST(SmtpHelpers, ComposeRfc5322ContainsHeadersAndBody) {
    Message m;
    m.from       = "noreply@app.example";
    m.from_name  = "Gestalt2";
    m.to         = "user@example.com";
    m.subject    = "Welcome";
    m.body_text  = "Hello!\nClick the link.";
    m.message_id = "abc-123";
    const auto s = compose_rfc5322(m);
    EXPECT_NE(s.find("From: \"Gestalt2\" <noreply@app.example>\r\n"), std::string::npos);
    EXPECT_NE(s.find("To: <user@example.com>\r\n"),                   std::string::npos);
    EXPECT_NE(s.find("Subject: Welcome\r\n"),                          std::string::npos);
    EXPECT_NE(s.find("Message-ID: <abc-123>\r\n"),                     std::string::npos);
    EXPECT_NE(s.find("\r\nHello!\r\nClick the link.\r\n"),              std::string::npos);
}

TEST(SmtpHelpers, DotStuffing) {
    Message m;
    m.from = "a@b"; m.to = "c@d"; m.subject = "x";
    m.body_text = ".dotline\nnormal\n.also-dot";
    const auto s = compose_rfc5322(m);
    // Each line starting with '.' should be doubled.
    EXPECT_NE(s.find("\r\n..dotline\r\n"),  std::string::npos);
    EXPECT_NE(s.find("\r\n..also-dot\r\n"), std::string::npos);
}

TEST(Mailer, CapturingMailerRecordsMessage) {
    CapturingMailer cap;
    Message m;
    m.from = "a@b"; m.to = "c@d"; m.subject = "hi"; m.body_text = "body";
    auto r = cap.send(m);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.smtp_status, 250);
    ASSERT_EQ(cap.sent.size(), 1u);
    EXPECT_EQ(cap.sent[0].subject, "hi");
}

TEST(Mailer, LogOnlyMailerAlwaysReturnsOk) {
    // Redirect to a temp file so we don't spam test logs.
    std::FILE* tmp = std::tmpfile();
    ASSERT_NE(tmp, nullptr);
    LogOnlyMailer m(tmp);
    Message msg{"a@b", "Sender", "c@d", "subj", "body", "id-1"};
    auto r = m.send(msg);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.smtp_status, 250);
    // Verify the file got non-empty content.
    std::fseek(tmp, 0, SEEK_END);
    EXPECT_GT(std::ftell(tmp), 0);
    std::fclose(tmp);
}

TEST(SmtpClient, MissingHostFailsCleanly) {
    SmtpConfig c;  // host empty
    SmtpClient client(c);
    Message m{"a@b", "", "c@d", "subj", "body", {}};
    auto r = client.send(m);
    EXPECT_FALSE(r.ok);
    EXPECT_FALSE(r.error.empty());
}

TEST(SmtpClient, InvalidAddressRejectedBeforeNetwork) {
    SmtpConfig c; c.host = "smtp.example.com";
    SmtpClient client(c);
    Message m{"not-an-email", "", "c@d", "x", "y", {}};
    auto r = client.send(m);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.error, "invalid address");
}
