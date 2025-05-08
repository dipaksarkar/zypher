#include <php_embed.h>
#include <zend_compile.h>
#include <zend_execute.h>
#include <stdio.h>

typedef struct
{
    uint32_t opcode;
    uint32_t lineno;
    uint32_t op1_type;
    uint32_t op1_value;
    uint32_t op2_type;
    uint32_t op2_value;
    uint32_t result_type;
    uint32_t result_value;
} zypher_serialized_op;

void serialize_opcodes(const zend_op_array *op_array, const char *output_file)
{
    FILE *fp = fopen(output_file, "wb");
    if (!fp)
    {
        perror("Unable to open output file");
        return;
    }

    for (uint32_t i = 0; i < op_array->last; ++i)
    {
        const zend_op *op = &op_array->opcodes[i];

        zypher_serialized_op s_op = {
            .opcode = op->opcode,
            .lineno = op->lineno,
            .op1_type = op->op1_type,
            .op1_value = op->op1.constant,
            .op2_type = op->op2_type,
            .op2_value = op->op2.constant,
            .result_type = op->result_type,
            .result_value = op->result.var};

        fwrite(&s_op, sizeof(s_op), 1, fp);
    }

    fclose(fp);
}

/**
 * Disassemble opcodes into a human-readable format
 * This function produces a detailed disassembly of the PHP opcodes
 * suitable for analysis and debugging of the Zypher system.
 */
void export_opcodes_text(const zend_op_array *op_array, const char *output_file)
{
    FILE *fp = fopen(output_file, "w");
    if (!fp)
    {
        perror("Unable to open disassembly output file");
        return;
    }

    // Output file header
    fprintf(fp, "Zypher Opcode Disassembly\n");
    fprintf(fp, "=======================\n\n");

    // Metadata section
    fprintf(fp, "Metadata:\n");
    fprintf(fp, "  Filename: %s\n", op_array->filename ? ZSTR_VAL(op_array->filename) : "<unknown>");
    fprintf(fp, "  Function: %s\n", op_array->function_name ? ZSTR_VAL(op_array->function_name) : "<main>");
    fprintf(fp, "  Opcode Count: %u\n", op_array->last);
    fprintf(fp, "  Variable Count: %u\n", op_array->last_var);
    fprintf(fp, "  Literals Count: %u\n\n", op_array->last_literal);

    // Literal table section if it exists
    if (op_array->literals && op_array->last_literal > 0)
    {
        fprintf(fp, "Literal Table:\n");
        fprintf(fp, "-------------\n");

        for (uint32_t i = 0; i < op_array->last_literal; i++)
        {
            zval *literal = &op_array->literals[i];
            fprintf(fp, "  [%u] Type: %d, Value: ", i, Z_TYPE_P(literal));

            // Print value based on zval type
            switch (Z_TYPE_P(literal))
            {
            case IS_NULL:
                fprintf(fp, "NULL\n");
                break;
            case IS_TRUE:
                fprintf(fp, "true\n");
                break;
            case IS_FALSE:
                fprintf(fp, "false\n");
                break;
            case IS_LONG:
                fprintf(fp, "%lld\n", (long long)Z_LVAL_P(literal));
                break;
            case IS_DOUBLE:
                fprintf(fp, "%f\n", Z_DVAL_P(literal));
                break;
            case IS_STRING:
                fprintf(fp, "\"%s\" (len=%zu)\n", Z_STRVAL_P(literal), Z_STRLEN_P(literal));
                break;
            default:
                fprintf(fp, "<complex type>\n");
                break;
            }
        }
        fprintf(fp, "\n");
    }

    // Output opcodes in detailed disassembly format
    fprintf(fp, "Opcodes Disassembly:\n");
    fprintf(fp, "-------------------\n");
    fprintf(fp, "%-4s %-20s %-5s %-20s %-20s %-20s\n",
            "Line", "Opcode", "ID", "OP1", "OP2", "Result");
    fprintf(fp, "-------------------------------------------------------------------\n");

    for (uint32_t i = 0; i < op_array->last; ++i)
    {
        char op1_str[64] = {0};
        char op2_str[64] = {0};
        char result_str[64] = {0};
        const zend_op *op = &op_array->opcodes[i];
        const char *opname = zend_get_opcode_name(op->opcode);

        // Format operands based on their types
        switch (op->op1_type)
        {
        case IS_CONST:
            snprintf(op1_str, sizeof(op1_str), "CONST(%d)", op->op1.constant);
            break;
        case IS_TMP_VAR:
            snprintf(op1_str, sizeof(op1_str), "TMP_VAR(%d)", op->op1.var);
            break;
        case IS_VAR:
            snprintf(op1_str, sizeof(op1_str), "VAR(%d)", op->op1.var);
            break;
        case IS_CV:
            snprintf(op1_str, sizeof(op1_str), "CV(%d)", op->op1.var);
            break;
        case IS_UNUSED:
            snprintf(op1_str, sizeof(op1_str), "UNUSED");
            break;
        default:
            snprintf(op1_str, sizeof(op1_str), "UNKNOWN(%d)", op->op1_type);
            break;
        }

        switch (op->op2_type)
        {
        case IS_CONST:
            snprintf(op2_str, sizeof(op2_str), "CONST(%d)", op->op2.constant);
            break;
        case IS_TMP_VAR:
            snprintf(op2_str, sizeof(op2_str), "TMP_VAR(%d)", op->op2.var);
            break;
        case IS_VAR:
            snprintf(op2_str, sizeof(op2_str), "VAR(%d)", op->op2.var);
            break;
        case IS_CV:
            snprintf(op2_str, sizeof(op2_str), "CV(%d)", op->op2.var);
            break;
        case IS_UNUSED:
            snprintf(op2_str, sizeof(op2_str), "UNUSED");
            break;
        default:
            snprintf(op2_str, sizeof(op2_str), "UNKNOWN(%d)", op->op2_type);
            break;
        }

        switch (op->result_type)
        {
        case IS_CONST:
            snprintf(result_str, sizeof(result_str), "CONST(%d)", op->result.constant);
            break;
        case IS_TMP_VAR:
            snprintf(result_str, sizeof(result_str), "TMP_VAR(%d)", op->result.var);
            break;
        case IS_VAR:
            snprintf(result_str, sizeof(result_str), "VAR(%d)", op->result.var);
            break;
        case IS_CV:
            snprintf(result_str, sizeof(result_str), "CV(%d)", op->result.var);
            break;
        case IS_UNUSED:
            snprintf(result_str, sizeof(result_str), "UNUSED");
            break;
        default:
            snprintf(result_str, sizeof(result_str), "UNKNOWN(%d)", op->result_type);
            break;
        }

        fprintf(fp, "%-4u %-20s %-5u %-20s %-20s %-20s\n",
                op->lineno, opname ? opname : "UNKNOWN", op->opcode,
                op1_str, op2_str, result_str);
    }

    // Add opcode verification checksum
    uint32_t checksum = 0;
    for (uint32_t i = 0; i < op_array->last; ++i)
    {
        const zend_op *op = &op_array->opcodes[i];
        checksum += op->opcode + op->lineno + op->op1_type + op->op2_type + op->result_type;
    }

    fprintf(fp, "\nOpcode Verification:\n");
    fprintf(fp, "  Checksum: 0x%08X\n", checksum);
    fprintf(fp, "  Opcode Count: %u\n", op_array->last);
    fprintf(fp, "\nGenerated with Zypher Encoder v1.0\n");

    fclose(fp);
}

int validate_opcode_binary(const char *binary_file)
{
    FILE *fp = fopen(binary_file, "rb");
    if (!fp)
    {
        perror("Unable to open binary file for validation");
        return -1;
    }

    // Check file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Calculate expected count of opcode structs
    size_t op_struct_size = sizeof(zypher_serialized_op);
    long expected_op_count = file_size / op_struct_size;

    // Validate that the file size is a multiple of struct size
    if (file_size % op_struct_size != 0)
    {
        printf("ERROR: Binary file size (%ld) is not a multiple of opcode struct size (%zu)\n",
               file_size, op_struct_size);
        fclose(fp);
        return -1;
    }

    printf("Binary validation passed: found %ld opcodes in file\n", expected_op_count);

    // Read a few opcodes for spot checking
    if (expected_op_count > 0)
    {
        printf("Sample of first opcode:\n");
        zypher_serialized_op first_op;
        if (fread(&first_op, sizeof(first_op), 1, fp) == 1)
        {
            printf("  Opcode: %u\n  Line: %u\n", first_op.opcode, first_op.lineno);
        }
    }

    fclose(fp);
    return 0;
}

// Hexdump utility function to visualize binary files
void hex_dump(const char *binary_file, const char *output_file)
{
    FILE *fp_in = fopen(binary_file, "rb");
    if (!fp_in)
    {
        perror("Unable to open binary file for hexdump");
        return;
    }

    FILE *fp_out = fopen(output_file, "w");
    if (!fp_out)
    {
        perror("Unable to open output file for hexdump");
        fclose(fp_in);
        return;
    }

    fprintf(fp_out, "Hexdump of %s\n", binary_file);
    fprintf(fp_out, "===========================================\n\n");
    fprintf(fp_out, "Offset    | Hexadecimal                      | ASCII\n");
    fprintf(fp_out, "------------------------------------------------------\n");

    unsigned char buffer[16];
    size_t bytes_read;
    size_t offset = 0;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp_in)) > 0)
    {
        fprintf(fp_out, "%08zX | ", offset);

        // Print hex values
        for (size_t i = 0; i < 16; i++)
        {
            if (i < bytes_read)
            {
                fprintf(fp_out, "%02X ", buffer[i]);
            }
            else
            {
                fprintf(fp_out, "   ");
            }
        }

        fprintf(fp_out, "| ");

        // Print ASCII representation
        for (size_t i = 0; i < bytes_read; i++)
        {
            if (buffer[i] >= 32 && buffer[i] <= 126)
            { // Printable ASCII
                fprintf(fp_out, "%c", buffer[i]);
            }
            else
            {
                fprintf(fp_out, ".");
            }
        }

        fprintf(fp_out, "\n");
        offset += bytes_read;
    }

    fprintf(fp_out, "\nTotal size: %zu bytes\n", offset);

    fclose(fp_in);
    fclose(fp_out);
}
