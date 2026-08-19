#include <Arduino.h>
#include <lvgl.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include "display.h"
#include "esp_bsp.h"
#include "lv_port.h"
#include "bip39.h"
#include "help.h"


// Header necessário para o widget QR Code do LVGL (v8)
#if __has_include("extra/widgets/qrcode/lv_qrcode.h")
#include "extra/widgets/qrcode/lv_qrcode.h"
#elif __has_include("lvgl/src/extra/widgets/qrcode/lv_qrcode.h")
#include "lvgl/src/extra/widgets/qrcode/lv_qrcode.h"
#endif
#define LVGL_PORT_ROTATION_DEGREE (90)

enum EntropyMethod {
    METHOD_DICE,
    METHOD_COIN
};

static int target_entropy_bits = 0; // 124 bits p/ 12 palavras | 248 bits p/ 24 palavras
static int total_entropy_bits = 0;  // 128 bits p/ 12 palavras | 256 bits p/ 24 palavras
static String entropy_bits = "";
static EntropyMethod selected_method = METHOD_DICE;
static String last_full_stream = "";

static lv_obj_t *label_status = NULL;
static lv_obj_t *label_bits = NULL;
static lv_obj_t *label_words_live = NULL;
static lv_obj_t *cont_words_live = NULL;

void create_selection_screen();
void create_method_screen();
void create_dice_screen();
void create_coin_screen();
void create_result_screen(String full_stream);
void create_qrcode_screen();
void create_about_screen();

const char* get_bip39_word(uint16_t index) {
    if (index < 2048) {
        return bip39_wordlist[index];
    }
    return "unknown";
}

// Converte a bitstream para string de mnemonic BIP-39
String get_mnemonic_phrase(String full_stream) {
    int total_words = (total_entropy_bits == 128) ? 12 : 24;
    String mnemonic = "";

    for (int i = 0; i < total_words; i++) {
        uint16_t word_index = 0;
        for (int b = 0; b < 11; b++) {
            if (full_stream[i * 11 + b] == '1') {
                word_index |= (1 << (10 - b));
            }
        }
        mnemonic += String(get_bip39_word(word_index));
        if (i < total_words - 1) mnemonic += " ";
    }
    return mnemonic;
}

String derive_bip32_master_key(String mnemonic_phrase) {
    uint8_t seed[64];
    String passphrase = "mnemonic"; // BIP39 salt prefix

    // 1. PBKDF2-HMAC-SHA512 (2048 iterações)
    // Passa MBEDTLS_MD_SHA512 diretamente como primeiro argumento
    mbedtls_pkcs5_pbkdf2_hmac_ext(
        MBEDTLS_MD_SHA512,
        (const unsigned char*)mnemonic_phrase.c_str(), mnemonic_phrase.length(),
        (const unsigned char*)passphrase.c_str(), passphrase.length(),
        2048, 64, seed
    );

    // 2. HMAC-SHA512 com a chave "Bitcoin seed"
    uint8_t hmac_output[64];
    const char* key = "Bitcoin seed";
    
    mbedtls_md_context_t sha512_ctx;
    mbedtls_md_init(&sha512_ctx);
    mbedtls_md_setup(&sha512_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
    mbedtls_md_hmac_starts(&sha512_ctx, (const unsigned char*)key, strlen(key));
    mbedtls_md_hmac_update(&sha512_ctx, seed, 64);
    mbedtls_md_hmac_finish(&sha512_ctx, hmac_output);
    mbedtls_md_free(&sha512_ctx);

    // Formata os primeiros 32 bytes da chave privada master em hexadecimal
    String priv_key_hex = "";
    for (int i = 0; i < 32; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hmac_output[i]);
        priv_key_hex += String(hex);
    }
    return priv_key_hex;
}

void generate_bip39_seed() {
    int cs_bits = (total_entropy_bits == 128) ? 4 : 8;
    int entropy_bytes_len = total_entropy_bits / 8;
    
    uint8_t entropy_bytes[32] = {0};

    for (int i = 0; i < target_entropy_bits; i++) {
        if (entropy_bits[i] == '1') {
            entropy_bytes[i / 8] |= (1 << (7 - (i % 8)));
        }
    }

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, entropy_bytes, entropy_bytes_len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    String full_stream = entropy_bits;
    for (int i = 0; i < cs_bits; i++) {
        uint8_t bit = (hash[0] >> (7 - i)) & 0x01;
        full_stream += String(bit);
    }

    last_full_stream = full_stream;
    create_result_screen(full_stream);
}

static void update_live_words() {
    if (!label_words_live) return;

    int current_len = entropy_bits.length();
    int complete_words = current_len / 11;

    // Buffer estático para evitar alocações dinâmicas no Heap
    static char live_text_buf[512];
    int pos = snprintf(live_text_buf, sizeof(live_text_buf), "Words:\n");

    for (int i = 0; i < complete_words && pos < (int)sizeof(live_text_buf) - 30; i++) {
        uint16_t word_index = 0;

        for (int b = 0; b < 11; b++) {
            if (entropy_bits[i * 11 + b] == '1') {
                word_index |= (1 << (10 - b));
            }
        }

        pos += snprintf(live_text_buf + pos, sizeof(live_text_buf) - pos, 
                        "%d. %s\n", i + 1, get_bip39_word(word_index));
    }

    lv_label_set_text(label_words_live, live_text_buf);

    if (cont_words_live) {
        lv_obj_scroll_to_y(cont_words_live, LV_COORD_MAX, LV_ANIM_OFF);
    }
}

static void update_status_labels() {
    int current_bits = entropy_bits.length();
    
    if (label_status) {
        char status_buf[32];
        snprintf(status_buf, sizeof(status_buf), "Bits: %d / %d", current_bits, target_entropy_bits);
        lv_label_set_text(label_status, status_buf);
    }

    if (label_bits) {
        if (current_bits > 0) {
            int start_idx = (current_bits > 20) ? (current_bits - 20) : 0;
            String recent = (current_bits > 20) ? "..." : "";
            recent += entropy_bits.substring(start_idx);
            lv_label_set_text(label_bits, recent.c_str());
        } else {
            lv_label_set_text(label_bits, "-");
        }
    }

    update_live_words();
}

static void add_bit_input(char bit_val) {
    entropy_bits += bit_val;
    update_status_labels();

    if (entropy_bits.length() >= target_entropy_bits) {
        generate_bip39_seed();
    }
}

static void btn_size_event_cb(lv_event_t * e) {
    lv_obj_t * btn = lv_event_get_target(e);
    int words = (intptr_t)lv_obj_get_user_data(btn);
    
    if (words == 12) {
        total_entropy_bits = 128;
        target_entropy_bits = 124;
    } else {
        total_entropy_bits = 256;
        target_entropy_bits = 248;
    }
    
    entropy_bits = "";
    create_method_screen();
}

static void btn_method_event_cb(lv_event_t * e) {
    lv_obj_t * btn = lv_event_get_target(e);
    int method = (intptr_t)lv_obj_get_user_data(btn);
    
    if (method == 0) {
        selected_method = METHOD_DICE;
        create_dice_screen();
    } else {
        selected_method = METHOD_COIN;
        create_coin_screen();
    }
}

static void btn_about_event_cb(lv_event_t * e) {
    create_about_screen();
}

static void btn_restart_event_cb(lv_event_t * e) {
    create_selection_screen();
}

static void btn_back_to_results_cb(lv_event_t * e) {
    create_result_screen(last_full_stream);
}

static void btn_qrcode_event_cb(lv_event_t * e) {
    create_qrcode_screen();
}

static void btn_dice_event_cb(lv_event_t * e) {
    lv_obj_t * btn = lv_event_get_target(e);
    int dice_val = (intptr_t)lv_obj_get_user_data(btn);
    char bit_val = (dice_val > 3) ? '1' : '0';
    add_bit_input(bit_val);
}

static void btn_coin_event_cb(lv_event_t * e) {
    lv_obj_t * btn = lv_event_get_target(e);
    int coin_val = (intptr_t)lv_obj_get_user_data(btn);
    char bit_val = (coin_val == 1) ? '1' : '0';
    add_bit_input(bit_val);
}

static void btn_undo_event_cb(lv_event_t * e) {
    if (entropy_bits.length() > 0) {
        entropy_bits.remove(entropy_bits.length() - 1);
        update_status_labels();
    }
}

void draw_dice_face(lv_obj_t * btn, int val) {
    const int dot_size = 10;
    const int offset = 22;

    const int pos[6][6][2] = {
        {{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}},
        {{-offset, -offset}, {offset, offset}, {0, 0}, {0, 0}, {0, 0}, {0, 0}},
        {{-offset, -offset}, {0, 0}, {offset, offset}, {0, 0}, {0, 0}, {0, 0}},
        {{-offset, -offset}, {offset, -offset}, {-offset, offset}, {offset, offset}, {0, 0}, {0, 0}},
        {{-offset, -offset}, {offset, -offset}, {0, 0}, {-offset, offset}, {offset, offset}, {0, 0}},
        {{-offset, -offset}, {offset, -offset}, {-offset, 0}, {offset, 0}, {-offset, offset}, {offset, offset}}
    };

    for (int i = 0; i < val; i++) {
        lv_obj_t * dot = lv_obj_create(btn);
        lv_obj_set_size(dot, dot_size, dot_size);
        lv_obj_set_style_radius(dot, LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_bg_color(dot, lv_color_black(), 0);
        lv_obj_set_style_border_width(dot, 0, 0);
        lv_obj_align(dot, LV_ALIGN_CENTER, pos[val - 1][i][0], pos[val - 1][i][1]);
        lv_obj_clear_flag(dot, LV_OBJ_FLAG_CLICKABLE);
    }
}

// Ecrã 1: Seleção de tamanho de Seed
void create_selection_screen() {
    lv_obj_t *scr = lv_obj_create(NULL);

    lv_obj_t * title = lv_label_create(scr);
    lv_label_set_text(title, "BIP39 Seed Generator");
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 20);

    lv_obj_t * btn12 = lv_btn_create(scr);
    lv_obj_set_size(btn12, 240, 50);
    lv_obj_align(btn12, LV_ALIGN_CENTER, 0, -50);
    lv_obj_set_user_data(btn12, (void*)12);
    lv_obj_add_event_cb(btn12, btn_size_event_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t * lbl12 = lv_label_create(btn12);
    lv_label_set_text(lbl12, "12 Words (128 Bits)");
    lv_obj_center(lbl12);

    lv_obj_t * btn24 = lv_btn_create(scr);
    lv_obj_set_size(btn24, 240, 50);
    lv_obj_align(btn24, LV_ALIGN_CENTER, 0, 10);
    lv_obj_set_user_data(btn24, (void*)24);
    lv_obj_add_event_cb(btn24, btn_size_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl24 = lv_label_create(btn24);
    lv_label_set_text(lbl24, "24 Words (256 Bits)");
    lv_obj_center(lbl24);

    lv_obj_t * btn_about = lv_btn_create(scr);
    lv_obj_set_size(btn_about, 140, 40);
    lv_obj_align(btn_about, LV_ALIGN_BOTTOM_MID, 0, -20);
    lv_obj_add_event_cb(btn_about, btn_about_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_about = lv_label_create(btn_about);
    lv_label_set_text(lbl_about, "About");
    lv_obj_center(lbl_about);

    lv_scr_load_anim(scr, LV_SCR_LOAD_ANIM_NONE, 0, 0, true);
}

// Ecrã Intermédio: Dados ou Moedas
void create_method_screen() {
    lv_obj_t *scr = lv_obj_create(NULL);

    lv_obj_t * btn_back = lv_btn_create(scr);
    lv_obj_set_size(btn_back, 70, 30);
    lv_obj_align(btn_back, LV_ALIGN_TOP_LEFT, 10, 5);
    lv_obj_add_event_cb(btn_back, btn_restart_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_back = lv_label_create(btn_back);
    lv_label_set_text(lbl_back, "< Back");
    lv_obj_center(lbl_back);

    lv_obj_t * title = lv_label_create(scr);
    lv_label_set_text(title, "Select Entropy Source");
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 20);

    lv_obj_t * btn_dice = lv_btn_create(scr);
    lv_obj_set_size(btn_dice, 220, 55);
    lv_obj_align(btn_dice, LV_ALIGN_CENTER, 0, -35);
    lv_obj_set_user_data(btn_dice, (void*)0);
    lv_obj_add_event_cb(btn_dice, btn_method_event_cb, LV_EVENT_CLICKED, NULL);
    
    lv_obj_t * lbl_dice = lv_label_create(btn_dice);
    lv_label_set_text(lbl_dice, "Dice (Dados)");
    lv_obj_center(lbl_dice);

    lv_obj_t * btn_coin = lv_btn_create(scr);
    lv_obj_set_size(btn_coin, 220, 55);
    lv_obj_align(btn_coin, LV_ALIGN_CENTER, 0, 35);
    lv_obj_set_user_data(btn_coin, (void*)1);
    lv_obj_add_event_cb(btn_coin, btn_method_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_coin = lv_label_create(btn_coin);
    lv_label_set_text(lbl_coin, "Coins (Moedas)");
    lv_obj_center(lbl_coin);

    lv_scr_load_anim(scr, LV_SCR_LOAD_ANIM_NONE, 0, 0, true);
}

// Ecrã de Entrada por Dados
void create_dice_screen() {
    lv_obj_t *scr = lv_obj_create(NULL);

    lv_obj_t * btn_back = lv_btn_create(scr);
    lv_obj_set_size(btn_back, 70, 30);
    lv_obj_align(btn_back, LV_ALIGN_TOP_LEFT, 10, 5);
    lv_obj_add_event_cb(btn_back, btn_restart_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_back = lv_label_create(btn_back);
    lv_label_set_text(lbl_back, "< Back");
    lv_obj_center(lbl_back);

    cont_words_live = lv_obj_create(scr);
    lv_obj_set_pos(cont_words_live, 10, 42);
    lv_obj_set_size(cont_words_live, 110, 265);
    lv_obj_set_scrollbar_mode(cont_words_live, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_set_scroll_dir(cont_words_live, LV_DIR_VER);

    label_words_live = lv_label_create(cont_words_live);
    lv_label_set_text(label_words_live, "Words:\n-");
    lv_obj_set_width(label_words_live, lv_pct(100));

    label_status = lv_label_create(scr);
    char buf[64];
    snprintf(buf, sizeof(buf), "Bits: 0 / %d", target_entropy_bits);
    lv_label_set_text(label_status, buf);
    lv_obj_align(label_status, LV_ALIGN_TOP_RIGHT, -15, 8);

    label_bits = lv_label_create(scr);
    lv_label_set_text(label_bits, "-");
    lv_obj_align(label_bits, LV_ALIGN_TOP_RIGHT, -15, 26);

    for (int i = 1; i <= 6; i++) {
        lv_obj_t * btn = lv_btn_create(scr);
        lv_obj_set_size(btn, 80, 80);
        lv_obj_set_style_bg_color(btn, lv_color_white(), 0);
        lv_obj_set_style_border_color(btn, lv_color_black(), 0);
        lv_obj_set_style_border_width(btn, 2, 0);

        int row = (i - 1) / 3;
        int col = (i - 1) % 3;
        
        lv_obj_align(btn, LV_ALIGN_CENTER, -75 + (col * 95), -15 + (row * 95));

        lv_obj_set_user_data(btn, (void*)(intptr_t)i);
        lv_obj_add_event_cb(btn, btn_dice_event_cb, LV_EVENT_CLICKED, NULL);

        draw_dice_face(btn, i);
    }

    lv_obj_t * btn_undo = lv_btn_create(scr);
    lv_obj_set_size(btn_undo, 60, 175);
    lv_obj_align(btn_undo, LV_ALIGN_CENTER, 205, 32);
    lv_obj_set_style_bg_color(btn_undo, lv_palette_main(LV_PALETTE_RED), 0);
    lv_obj_add_event_cb(btn_undo, btn_undo_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_undo = lv_label_create(btn_undo);
    lv_label_set_text(lbl_undo, "UNDO");
    lv_obj_center(lbl_undo);

    lv_scr_load_anim(scr, LV_SCR_LOAD_ANIM_NONE, 0, 0, true);
}

// Ecrã de Entrada por Moedas (Redondos, mais pequenos e afastados da lista)
void create_coin_screen() {
    lv_obj_t *scr = lv_obj_create(NULL);

    lv_obj_t * btn_back = lv_btn_create(scr);
    lv_obj_set_size(btn_back, 70, 30);
    lv_obj_align(btn_back, LV_ALIGN_TOP_LEFT, 10, 5);
    lv_obj_add_event_cb(btn_back, btn_restart_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_back = lv_label_create(btn_back);
    lv_label_set_text(lbl_back, "< Back");
    lv_obj_center(lbl_back);

    cont_words_live = lv_obj_create(scr);
    lv_obj_set_pos(cont_words_live, 10, 42);
    lv_obj_set_size(cont_words_live, 110, 265);
    lv_obj_set_scrollbar_mode(cont_words_live, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_set_scroll_dir(cont_words_live, LV_DIR_VER);

    label_words_live = lv_label_create(cont_words_live);
    lv_label_set_text(label_words_live, "Words:\n-");
    lv_obj_set_width(label_words_live, lv_pct(100));

    label_status = lv_label_create(scr);
    char buf[64];
    snprintf(buf, sizeof(buf), "Bits: 0 / %d", target_entropy_bits);
    lv_label_set_text(label_status, buf);
    lv_obj_align(label_status, LV_ALIGN_TOP_RIGHT, -15, 8);

    label_bits = lv_label_create(scr);
    lv_label_set_text(label_bits, "-");
    lv_obj_align(label_bits, LV_ALIGN_TOP_RIGHT, -15, 26);

    // Botão HEADS (Redondo, 100x100, afastado da esquerda)
    lv_obj_t * btn_heads = lv_btn_create(scr);
    lv_obj_set_size(btn_heads, 100, 100);
    lv_obj_set_style_radius(btn_heads, LV_RADIUS_CIRCLE, 0);
    lv_obj_align(btn_heads, LV_ALIGN_CENTER, -30, 32);
    lv_obj_set_user_data(btn_heads, (void*)1);
    lv_obj_add_event_cb(btn_heads, btn_coin_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_heads = lv_label_create(btn_heads);
    lv_label_set_text(lbl_heads, "HEADS\n(1)");
    lv_obj_set_style_text_align(lbl_heads, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(lbl_heads);

    // Botão TAILS (Redondo, 100x100, afastado da esquerda)
    lv_obj_t * btn_tails = lv_btn_create(scr);
    lv_obj_set_size(btn_tails, 100, 100);
    lv_obj_set_style_radius(btn_tails, LV_RADIUS_CIRCLE, 0);
    lv_obj_align(btn_tails, LV_ALIGN_CENTER, 80, 32);
    lv_obj_set_user_data(btn_tails, (void*)0);
    lv_obj_add_event_cb(btn_tails, btn_coin_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_tails = lv_label_create(btn_tails);
    lv_label_set_text(lbl_tails, "TAILS\n(0)");
    lv_obj_set_style_text_align(lbl_tails, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(lbl_tails);

    // Botão UNDO
    lv_obj_t * btn_undo = lv_btn_create(scr);
    lv_obj_set_size(btn_undo, 60, 175);
    lv_obj_align(btn_undo, LV_ALIGN_CENTER, 205, 32);
    lv_obj_set_style_bg_color(btn_undo, lv_palette_main(LV_PALETTE_RED), 0);
    lv_obj_add_event_cb(btn_undo, btn_undo_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_undo = lv_label_create(btn_undo);
    lv_label_set_text(lbl_undo, "UNDO");
    lv_obj_center(lbl_undo);

    lv_scr_load_anim(scr, LV_SCR_LOAD_ANIM_NONE, 0, 0, true);
}

void create_about_screen() {
    lv_obj_t *scr = lv_obj_create(NULL);

    lv_obj_t * title = lv_label_create(scr);
    lv_label_set_text(title, "About & Help");
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

    lv_obj_t * ta_help = lv_textarea_create(scr);
    lv_obj_set_size(ta_help, 420, 200);
    lv_obj_align(ta_help, LV_ALIGN_CENTER, 0, -10);
    lv_textarea_set_text(ta_help, HELP_TEXT);

    lv_obj_t * btn_back = lv_btn_create(scr);
    lv_obj_set_size(btn_back, 120, 40);
    lv_obj_align(btn_back, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_add_event_cb(btn_back, btn_restart_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_back = lv_label_create(btn_back);
    lv_label_set_text(lbl_back, "Back");
    lv_obj_center(lbl_back);

    lv_scr_load_anim(scr, LV_SCR_LOAD_ANIM_NONE, 0, 0, true);
}

// Ecrã de Resultados com Botão para QR Code
void create_result_screen(String full_stream) {
    lv_obj_t *scr = lv_obj_create(NULL);

    lv_obj_t * title = lv_label_create(scr);
    lv_label_set_text(title, "Generated Seed Phrase");
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 5);

    int total_words = (total_entropy_bits == 128) ? 12 : 24;
    lv_obj_t * table = lv_table_create(scr);
    
    lv_obj_set_style_text_font(table, &lv_font_montserrat_12, LV_PART_ITEMS);
    lv_obj_set_style_pad_top(table, 2, LV_PART_ITEMS);
    lv_obj_set_style_pad_bottom(table, 2, LV_PART_ITEMS);
    lv_obj_set_style_pad_left(table, 4, LV_PART_ITEMS);
    lv_obj_set_style_pad_right(table, 4, LV_PART_ITEMS);

    if (total_words == 12) {
        lv_obj_set_size(table, 440, 210);
        lv_obj_align(table, LV_ALIGN_CENTER, 0, -15);

        lv_table_set_col_width(table, 0, 220);
        lv_table_set_col_width(table, 1, 200);

        for (int i = 0; i < 12; i++) {
            uint16_t word_index = 0;
            String word_bits = "";

            for (int b = 0; b < 11; b++) {
                char bit = full_stream[i * 11 + b];
                word_bits += bit;
                if (bit == '1') {
                    word_index |= (1 << (10 - b));
                }
            }

            String word_cell = String(i + 1) + ". " + String(get_bip39_word(word_index));
            lv_table_set_cell_value(table, i, 0, word_cell.c_str());
            lv_table_set_cell_value(table, i, 1, word_bits.c_str());
        }
    } else {
        lv_obj_set_size(table, 460, 210);
        lv_obj_align(table, LV_ALIGN_CENTER, 0, -15);

        lv_table_set_col_width(table, 0, 130);
        lv_table_set_col_width(table, 1, 95);
        lv_table_set_col_width(table, 2, 130);
        lv_table_set_col_width(table, 3, 95);

        for (int i = 0; i < 12; i++) {
            uint16_t word_index_left = 0;
            String bits_left = "";
            for (int b = 0; b < 11; b++) {
                char bit = full_stream[i * 11 + b];
                bits_left += bit;
                if (bit == '1') word_index_left |= (1 << (10 - b));
            }
            String cell_left = String(i + 1) + ". " + String(get_bip39_word(word_index_left));
            lv_table_set_cell_value(table, i, 0, cell_left.c_str());
            lv_table_set_cell_value(table, i, 1, bits_left.c_str());

            int r_idx = i + 12;
            uint16_t word_index_right = 0;
            String bits_right = "";
            for (int b = 0; b < 11; b++) {
                char bit = full_stream[r_idx * 11 + b];
                bits_right += bit;
                if (bit == '1') word_index_right |= (1 << (10 - b));
            }
            String cell_right = String(r_idx + 1) + ". " + String(get_bip39_word(word_index_right));
            lv_table_set_cell_value(table, i, 2, cell_right.c_str());
            lv_table_set_cell_value(table, i, 3, bits_right.c_str());
        }
    }

    // Botão Start Over
    lv_obj_t * btn_restart = lv_btn_create(scr);
    lv_obj_set_size(btn_restart, 130, 35);
    lv_obj_align(btn_restart, LV_ALIGN_BOTTOM_LEFT, 20, -5);
    lv_obj_add_event_cb(btn_restart, btn_restart_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_restart = lv_label_create(btn_restart);
    lv_label_set_text(lbl_restart, "Start Over");
    lv_obj_center(lbl_restart);

    // Botão Show QR Code
    lv_obj_t * btn_qr = lv_btn_create(scr);
    lv_obj_set_size(btn_qr, 150, 35);
    lv_obj_align(btn_qr, LV_ALIGN_BOTTOM_RIGHT, -20, -5);
    lv_obj_set_style_bg_color(btn_qr, lv_palette_main(LV_PALETTE_BLUE), 0);
    lv_obj_add_event_cb(btn_qr, btn_qrcode_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_qr = lv_label_create(btn_qr);
    lv_label_set_text(lbl_qr, "Show QR Code");
    lv_obj_center(lbl_qr);

    lv_scr_load_anim(scr, LV_SCR_LOAD_ANIM_NONE, 0, 0, true);
}

// Ecrã com QR Code da Chave Privada
void create_qrcode_screen() {
    lv_obj_t *scr = lv_obj_create(NULL);

    // Botão de Voltar para o Ecrã de Resultados
    lv_obj_t * btn_back = lv_btn_create(scr);
    lv_obj_set_size(btn_back, 70, 30);
    lv_obj_align(btn_back, LV_ALIGN_TOP_LEFT, 10, 5);
    lv_obj_add_event_cb(btn_back, btn_back_to_results_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t * lbl_back = lv_label_create(btn_back);
    lv_label_set_text(lbl_back, "< Back");
    lv_obj_center(lbl_back);

    lv_obj_t * title = lv_label_create(scr);
    lv_label_set_text(title, "Private Key QR Code");
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

    // Derivação da Seed Mnemonic e Master Private Key
    String mnemonic = get_mnemonic_phrase(last_full_stream);
    String priv_key_hex = derive_bip32_master_key(mnemonic);

    // QR Code em LVGL (Compatível com formato standard de importação)
    lv_obj_t * qrcode = lv_qrcode_create(scr, 170, lv_color_black(), lv_color_white());
    lv_qrcode_update(qrcode, priv_key_hex.c_str(), priv_key_hex.length());
    lv_obj_align(qrcode, LV_ALIGN_CENTER, 0, -5);

    lv_obj_t * label_info = lv_label_create(scr);
    lv_label_set_text(label_info, "Scan with Soft Wallet to import Master Key");
    lv_obj_set_style_text_font(label_info, &lv_font_montserrat_12, 0);
    lv_obj_align(label_info, LV_ALIGN_BOTTOM_MID, 0, -10);

    lv_scr_load_anim(scr, LV_SCR_LOAD_ANIM_NONE, 0, 0, true);
}

void setup()
{
    Serial.begin(115200);

    bsp_display_cfg_t cfg = {
        .lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG(),
        .buffer_size = EXAMPLE_LCD_QSPI_H_RES * EXAMPLE_LCD_QSPI_V_RES,
#if LVGL_PORT_ROTATION_DEGREE == 90
        .rotate = LV_DISP_ROT_90,
#elif LVGL_PORT_ROTATION_DEGREE == 270
        .rotate = LV_DISP_ROT_270,
#elif LVGL_PORT_ROTATION_DEGREE == 180
        .rotate = LV_DISP_ROT_180,
#elif LVGL_PORT_ROTATION_DEGREE == 0
        .rotate = LV_DISP_ROT_NONE,
#endif
    };

    bsp_display_start_with_config(&cfg);
    bsp_display_backlight_on();

    bsp_display_lock(0);
    create_selection_screen();
    bsp_display_unlock();
}

void loop()
{
    lv_timer_handler(); // Executa as tarefas pendentes da GUI
    vTaskDelay(pdMS_TO_TICKS(5)); // Evita o disparo do Watchdog Timer
}