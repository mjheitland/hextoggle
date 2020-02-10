// required for Visual Studio to compile
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#if !_MSC_VER
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/resource.h>
#endif

const char *header = "| hextoggle output file";
#define HEADER_LENGTH 23

#define EXIT_INVALID_ARGS 1
#define EXIT_FAILED_TO_OPEN_FILES 2
#define EXIT_FAILED_CLEANUP 3
#define EXIT_INVALID_INPUT 4
#define EXIT_ASSERTION_FAILED 5

/// Validates the given command-line arguments, and prints usage description on error.
/// @return 0 on success, EXIT_INVALID_ARGS on error
static int check_args(int argc, const char *argv[]) {
    if (argc == 2 || argc == 3)
        return 0;

    fprintf(stderr, "Usage: hextoggle [file] # toggles file in-place\n");
    fprintf(stderr, "       hextoggle [input] [output]\n");
    fprintf(stderr, "       hextoggle --dry-run [input]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Return codes:\n");
    fprintf(stderr, "  %i   success\n", EXIT_SUCCESS);
    fprintf(stderr, "  %i   invalid arguments\n", EXIT_INVALID_ARGS);
    fprintf(stderr, "  %i   failed to open input files\n", EXIT_FAILED_TO_OPEN_FILES);
    fprintf(stderr, "  %i   failed to clean up files\n", EXIT_FAILED_CLEANUP);
    fprintf(stderr, "  %i   invalid input\n", EXIT_INVALID_INPUT);
    fprintf(stderr, "  %i   internal assertion failed\n", EXIT_ASSERTION_FAILED);

    return EXIT_INVALID_ARGS;
}

#if _MSC_VER
#define TEMP_FILENAME_SIZE L_tmpnam
#else
#define TEMP_FILENAME_SIZE 25
#endif

/// Create and open a new temporary file with the given mode.
/// @param mode the mode to open the file with (such as "wb")
/// @param filename a butter of size TEMP_FILENAME_SIZE where the filename will be stored.
/// @return A handle to the open file. The temporary file's name will be stored in the given buffer.
///   Returns NULL on error.
static FILE *open_temporary_file(const char *mode, char filename[]) {
#if _MSC_VER
    int success = tmpnam(filename) == NULL;
#else
    strcpy(filename, ".temp_hextoggle_XXXXXXXX");
    int fd = mkstemp(filename);
    int success = fd != -1;
#endif
    if (!success) {
        fprintf(stderr, "Unable to get temp file name: %s\n", strerror(errno));
        return NULL;
    }
#if _MSC_VER
    FILE *file = fopen(filename, mode);
#else
    FILE *file = fdopen(fd, mode);
#endif
    if (!file) {
        fprintf(stderr, "Unable to open temporary file %s for writing: %s\n", filename, strerror(errno));
        remove(filename);
        return NULL;
    }
    return file;
}

static int cleanup_files(FILE *input, FILE *temp_output,
                  const char *temp_output_filename,
                  const char *real_output_filename) {
    if (temp_output) {
        fclose(temp_output);
    }
    fclose(input);
    if (!real_output_filename)
        return 0;
#if _MSC_VER
    if (-1 == remove(real_output_filename)) {
        if (errno != ENOENT) {
            // target file does exist but we cannot delete it
            fprintf(stderr, "Unable to remove file %s: %s\n", temp_output_filename, strerror(errno));
            return 1;
        }
    }
#endif
    if (-1 == rename(temp_output_filename, real_output_filename)) {
        fprintf(stderr, "Unable to rename file %s to %s: %s\n", temp_output_filename, real_output_filename, strerror(errno));
        return 1;
    }
    return 0;
}

static int hex_char_to_int(char c) {
    // c must match [0-9A-F]
    if (c >= '0' && c <= '9')
        return c - '0';
    else
        return c - 'a' + 10;
}
static char to_hex(char c) {
    // c in range 0-15
    if (c >= 0 && c <= 9)
        return c + '0';
    else
        return c - 10 + 'a';
}

// [000000000 00000000000]4865 6c6c 6f2c 2057 6f72 6c64 210a 0a23 |Hello, World!..#\n
// 0         1         2         3         4         5         6         7         8
// 012345678901234567890123456789012345678901234567890123456789012345678901234567890
static void char_block_to_hex(char *data, uint64_t data_size, uint64_t addr, char *output) {
    output[0] = '[';
    for (int shift_amount = (9 - 1) * 4, i = 1; shift_amount >= 0; shift_amount -= 4, ++i) {
        char c = (addr >> shift_amount) & 0xF;
        if (c >= 0 && c <= 9)
            output[i] = c + '0';
        else
            output[i] = c - 10 + 'a';
    }
    output[10] = ' ';
    for (int i = 21; i >= 11; --i) {
        output[i] = '0' + addr % 10;
        addr /= 10;
    }
    output[22] = ']';
    for (int i = 23, j = 0, k = 0, l = 0; i < 63; ++i, ++k) {
        if (k % 5 == 4 || j >= data_size) {
            output[i] = ' ';
        } else {
            if (l % 2 == 0) {
                output[i] = to_hex((data[j] >> 4) & 0x0F);
            } else {
                output[i] = to_hex(data[j] & 0x0F);
                ++j;
            }
            ++l;
        }
    }
    output[63] = '|';
    for (int i = 0; i < data_size; ++i)
        output[64 + i] = data[i] >= ' ' && data[i] <= '~' ? data[i] : '.';
    for (uint64_t i = data_size; i < 16; ++i)
        output[64 + i] = ' ';
    output[80] = '\n';
}

static uint64_t char_blocks_to_hex(char *data, uint64_t data_size, uint64_t addr, char *output) {
    uint64_t block_idx = 0;
    for (uint64_t block_offset = 0; block_offset < data_size; block_offset += 16) {
        uint64_t block_size = data_size - block_offset < 16 ? data_size - block_offset : 16;
        char_block_to_hex(data + block_offset, block_size, addr + block_offset, output + 81 * block_idx);
        ++block_idx;
    }
    return block_idx;
}

typedef struct {
    char prev_byte;
    bool skip_line;
    bool inside_comment;
} from_hex_data;

static from_hex_data init_from_hex_data() {
    return (from_hex_data) {
        .prev_byte = 0,
        .skip_line = false,
        .inside_comment = false
    };
}

static int hex_to_chars(from_hex_data *data, char c, FILE *output_stream) {
    if (data->prev_byte) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            char output = hex_char_to_int(data->prev_byte) << 4;
            output += hex_char_to_int((char)tolower(c));
            if (output_stream)
                fputc(output, output_stream);
            data->prev_byte = 0;
            return 0;
        } else {
            return 1;
        }
    }
    if (data->skip_line && c != '\n')
        return 0;
    if (c == '\n') {
        data->skip_line = false;
        return 0;
    }
    if (c == '|') {
        data->skip_line = true;
        return 0;
    }
    if (c == '[') {
        data->inside_comment = true;
        return 0;
    }
    if (data->inside_comment && c == ']') {
        data->inside_comment = false;
        return 0;
    }
    if (data->inside_comment)
        return 0;
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
        data->prev_byte = (char)tolower(c);
        return 0;
    }
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t')
        return 0;
    return 1;
}

// Return values: 0 for success, 1 for retry as to_hex, 2 for error
static int try_from_hex(FILE *input_file, FILE *output_file, char *output_filename_buffer,
                 char *from_hex_read_buffer, int *from_hex_read_buffer_length) {
    int ci;
    uint64_t i = 0;
    uint64_t line_no = 1, col_no = 0;
    from_hex_data data = init_from_hex_data();
    while ((ci = fgetc(input_file)) != EOF) {
        char c = (char)ci;
        if (c == '\n') {
            ++line_no;
            col_no = 0;
        } else {
            ++col_no;
        }
        if (i < HEADER_LENGTH) {
            from_hex_read_buffer[*from_hex_read_buffer_length] = c;
            ++*from_hex_read_buffer_length;
            if (header[i] != c) {
                return 1;
            }
        }
        if (hex_to_chars(&data, c, output_file)) {
            fprintf(stderr, "Invalid format at character %llu, line %llu, col %llu, aborting\n", i, line_no, col_no);
            return 2;
        }
        ++i;
    }
    if (i < HEADER_LENGTH) {
        // header was incomplete (or file was empty)
        return 1;
    }
    
    return 0;
}

static int try_to_hex(FILE *input_file, FILE *output_file, char *output_filename_buffer,
               const char *from_hex_read_buffer, int from_hex_read_buffer_length) {
    if (output_file) {
        fputs(header, output_file);
        fputc('\n', output_file);
    }
    
#define BLOCK_SIZE 16
    uint64_t addr = 0;
    char output[81 * BLOCK_SIZE];
    char input[16 * BLOCK_SIZE];
    
    // read in chars already read in by try_from_hex
    memcpy(input, from_hex_read_buffer, from_hex_read_buffer_length);
    
    while (true) {
        size_t i = from_hex_read_buffer_length
            + fread(input + from_hex_read_buffer_length,
                    1,
                    16 * BLOCK_SIZE - from_hex_read_buffer_length,
                    input_file);
        from_hex_read_buffer_length = 0;
        uint64_t blocks = char_blocks_to_hex(input, i, addr, output);
        addr += i;
        if (output_file) {
            fwrite(output, 81 * blocks, 1, output_file);
        }
        if (i < 16 * BLOCK_SIZE)
            break;
    }
    return 0;
}

static void get_filenames(const char **input_filename,
                   const char **output_filename,
                   int argc, const char *argv[]) {
    *input_filename = argv[1];
    *output_filename = argc == 3 ? argv[2] : argv[1];
    if (argc == 3 && strcmp(argv[1], "--dry-run") == 0) {
        *input_filename = argv[2];
        *output_filename = NULL;
    }
}

static int open_files(FILE **input_file, FILE **output_file,
               const char *input_filename, const char *output_filename,
               char *output_filename_buffer) {
    *output_file = NULL;
    if (output_filename) {
        *output_file = open_temporary_file("wb", output_filename_buffer);
    }
    
    *input_file = fopen(input_filename, "rb");
    if (!*input_file) {
        fprintf(stderr, "Unable to open file %s for reading: %s\n", input_filename, strerror(errno));
        if (*output_file) {
            fclose(*output_file);
            remove(output_filename_buffer);
        }
        return EXIT_FAILED_TO_OPEN_FILES;
    }
    return 0;
}

int main(int argc, const char *argv[]) {
    if (check_args(argc, argv))
        return EXIT_INVALID_ARGS;

    const char *input_filename;
    const char *output_filename;
    get_filenames(&input_filename, &output_filename, argc, argv);

    FILE *input_file, *output_file;
    char output_filename_buffer[TEMP_FILENAME_SIZE];
    if (open_files(&input_file, &output_file,
                   input_filename, output_filename, output_filename_buffer)) {
        return EXIT_FAILED_TO_OPEN_FILES;
    }
    
    // store read characters in case we need to retry as to_hex.
    int from_hex_read_buffer_length = 0;
    char from_hex_read_buffer[HEADER_LENGTH] = {0};
    
    int res = try_from_hex(input_file, output_file, output_filename_buffer, from_hex_read_buffer, &from_hex_read_buffer_length);
    switch (res) {
        case 0: // success
            if (cleanup_files(input_file, output_file, output_filename_buffer, output_filename))
                return EXIT_FAILED_CLEANUP;
            return EXIT_SUCCESS;
        case 2: // failure
            fclose(input_file);
            if (output_file) {
                fclose(output_file);
                remove(output_filename_buffer);
            }
            return EXIT_INVALID_INPUT;
        case 1: // retry
            res = try_to_hex(input_file, output_file, output_filename_buffer, from_hex_read_buffer, from_hex_read_buffer_length);
            if (res == 0) {
                if (cleanup_files(input_file, output_file, output_filename_buffer, output_filename)) {
                    return EXIT_FAILED_CLEANUP;
                }
                return EXIT_SUCCESS;
            }
            fclose(input_file);
            if (output_file) {
                fclose(output_file);
                remove(output_filename_buffer);
            }
            return EXIT_INVALID_INPUT;
    }
    return EXIT_ASSERTION_FAILED;
}
