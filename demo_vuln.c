// Demo file with multiple vulnerability patterns for Stage 1.

#include <stdio.h>
#include <string.h>

typedef struct {
    int id;
    char name[64];
    char email[128];
} User;

static void print_banner(void) {
    printf("=== Demo Vulnerable Program ===\n");
}

static void log_info(const char *msg) {
    printf("[INFO] %s\n", msg);
}

static void log_warn(const char *msg) {
    printf("[WARN] %s\n", msg);
}

static void safe_copy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) {
        return;
    }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static void fill_user(User *u, int id, const char *name, const char *email) {
    u->id = id;
    safe_copy(u->name, name, sizeof(u->name));
    safe_copy(u->email, email, sizeof(u->email));
}

static void print_user(const User *u) {
    printf("User{id=%d, name=%s, email=%s}\n", u->id, u->name, u->email);
}

static void debug_dump_buffer(const char *buf, size_t len) {
    size_t i;
    printf("Buffer dump (%zu bytes):\n", len);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n%04zu: ", i);
        }
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n");
}

static int compute_score(int a, int b) {
    int score = (a * 3) + (b * 2) - (a / 2);
    if (score < 0) {
        score = 0;
    }
    return score;
}

static void build_query(char *out, size_t out_size, const char *user_input) {
    (void)out_size;
    sprintf(out, "SELECT * FROM users WHERE name = '%s'", user_input);
}

static void render_html(char *out, size_t out_size, const char *user_input) {
    (void)out_size;
    // innerHTML = user_input;
    sprintf(out, "<div>%s</div>", user_input);
}

static void copy_untrusted(char *dst, const char *src) {
    strcpy(dst, src);
}

static void copy_untrusted_bytes(char *dst, const char *src) {
    memcpy(dst, src, strlen(src));
}

static void print_config(void) {
    log_info("Loading configuration...");
    log_info("Configuration loaded.");
}

static void process_metrics(int count) {
    int i;
    for (i = 0; i < count; i++) {
        if (i % 5 == 0) {
            log_info("Heartbeat");
        }
    }
}

static void handle_request(const char *user_input) {
    char small_buf[8];
    char query[512];
    char html[512];

    copy_untrusted(small_buf, user_input);
    copy_untrusted_bytes(small_buf, user_input);
    build_query(query, sizeof(query), user_input);
    render_html(html, sizeof(html), user_input);

    printf("Query: %s\n", query);
    printf("HTML: %s\n", html);
}

static void test_users(void) {
    User u1;
    User u2;
    fill_user(&u1, 1, "Alice", "alice@example.com");
    fill_user(&u2, 2, "Bob", "bob@example.com");
    print_user(&u1);
    print_user(&u2);
}

static void compute_batch(void) {
    int i;
    int total = 0;
    for (i = 0; i < 50; i++) {
        total += compute_score(i, i + 1);
    }
    printf("Batch score: %d\n", total);
}

static void generate_report(const char *title) {
    int i;
    printf("=== Report: %s ===\n", title);
    for (i = 0; i < 10; i++) {
        printf("Line %d: OK\n", i + 1);
    }
}

static void fake_io(void) {
    char buf[32] = "demo";
    debug_dump_buffer(buf, strlen(buf));
}

// Stage 2 demo: business-logic flaws
static int apply_coupon_after_checkout(int paid, int coupon_applied) {
    int total = 100;
    if (paid) {
        total = 0; // Paid already, but we still allow coupon to reduce total
    }
    if (coupon_applied) {
        total = total - 100; // This can make total negative (free purchase)
    }
    return total;
}

// Stage 2 demo: missing authorization check
static void view_admin_report(int is_admin) {
    (void)is_admin;
    // No authorization check before showing admin report
    printf("Admin report: all user emails...\n");
}

static void print_footer(void) {
    printf("=== End of Demo ===\n");
}

int main(int argc, char **argv) {
    char user_input[256] = "test";
    char password_buf[32];
    const char *fallback_input = "guest";

    const char *password = "P@ssw0rd!";
    safe_copy(password_buf, password, sizeof(password_buf));

    print_banner();
    print_config();
    test_users();
    compute_batch();
    process_metrics(25);
    generate_report("Weekly");
    fake_io();

    if (argc > 1) {
        safe_copy(user_input, argv[1], sizeof(user_input));
    } else {
        safe_copy(user_input, fallback_input, sizeof(user_input));
    }

    handle_request(user_input);
    // Stage 2 logic issues for LLM reasoning
    (void)apply_coupon_after_checkout(1, 1);
    view_admin_report(0);
    log_warn("Demo completed with potential vulnerabilities.");
    print_footer();
    return 0;
}
