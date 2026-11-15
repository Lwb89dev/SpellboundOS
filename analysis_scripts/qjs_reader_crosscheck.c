/* Independently authored structural harness for QuickJS 2020-07-05.
 * Include from a verified upstream source directory. No bytecode evaluation.
 * Nine header fields are printed in constant-pool depth-first order.
 */
#include "quickjs.c"
#undef malloc
#undef free
#undef realloc

static int dump_functions(JSValueConst value, const char *file, int *index) {
    if (JS_VALUE_GET_TAG(value) != JS_TAG_FUNCTION_BYTECODE) return 0;
    JSFunctionBytecode *b = JS_VALUE_GET_PTR(value);
    int count = 1;
    printf("FN\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
           file, (*index)++, b->arg_count, b->var_count, b->defined_arg_count,
           b->stack_size, b->closure_var_count, b->cpool_count,
           b->byte_code_len, b->js_mode, b->has_debug);
    for (int i = 0; i < b->cpool_count; ++i)
        count += dump_functions(b->cpool[i], file, index);
    return count;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int failed = 0;
    for (int i = 1; i < argc; ++i) {
        FILE *file = fopen(argv[i], "rb");
        if (!file) return 2;
        if (fseek(file, 0, SEEK_END)) { fclose(file); return 2; }
        long size = ftell(file);
        if (size <= 0 || size > 32 * 1024 * 1024 || fseek(file, 0, SEEK_SET)) {
            fclose(file); return 2;
        }
        uint8_t *data = malloc((size_t)size);
        if (!data) { fclose(file); return 2; }
        size_t read_size = fread(data, 1, (size_t)size, file);
        fclose(file);
        if (read_size != (size_t)size) { free(data); return 2; }
        JSRuntime *rt = JS_NewRuntime();
        if (!rt) { free(data); return 2; }
        JS_SetMemoryLimit(rt, 256 * 1024 * 1024);
        JS_SetMaxStackSize(rt, 512 * 1024);
        JSContext *ctx = JS_NewContext(rt);
        if (!ctx) { JS_FreeRuntime(rt); free(data); return 2; }
        JSValue object = JS_ReadObject(ctx, data, (size_t)size, JS_READ_OBJ_BYTECODE);
        if (JS_IsException(object)) {
            fprintf(stderr, "READ_ERROR\t%s\n", argv[i]);
            JSValue error = JS_GetException(ctx);
            JS_FreeValue(ctx, error);
            failed = 1;
        } else {
            int index = 0;
            int count = dump_functions(object, argv[i], &index);
            printf("%s\tOK\tfunctions=%d\n", argv[i], count);
            JS_FreeValue(ctx, object);
        }
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
        free(data);
    }
    return failed;
}
