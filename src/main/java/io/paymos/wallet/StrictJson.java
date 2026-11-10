package io.paymos.wallet;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigDecimal;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;

/**
 * JSON for the blind-sign guard, read the way the on-chain verifier reads it.
 *
 * <p>{@code JsonParser.parseString} parses LENIENTLY — unquoted names, single quotes, comments —
 * and keeps the LAST of a repeated object key. The guard approves a message whose exact bytes the
 * verifier parses again with a strict reader that rejects a repeated field, so a message naming
 * one key twice says two things. This reader takes RFC 8259 JSON only, refuses a key repeated in
 * one object at any depth, and refuses nesting deeper than {@link #MAX_DEPTH}: it recurses per
 * level, and the input comes from the server the guard does not trust.
 *
 * <p>(Key case is not the issue in this language: Gson keeps {@code "intents"} and {@code
 * "Intents"} as two keys and the guard reads the exact one, as the verifier does.)
 */
final class StrictJson {
    /** A transfer message is four levels deep; the limit is generous and still bounds the stack. */
    static final int MAX_DEPTH = 64;

    private StrictJson() {}

    /** Parses exactly one JSON document strictly. Every failure is a {@link PaymosException}. */
    static JsonElement parse(String json) {
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            reader.setStrictness(Strictness.STRICT);
            JsonElement value = read(reader, 0);
            if (reader.peek() != com.google.gson.stream.JsonToken.END_DOCUMENT)
                throw new PaymosException("unexpected data after the JSON document");
            return value;
        } catch (PaymosException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new PaymosException(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    private static JsonElement read(JsonReader reader, int depth) throws IOException {
        switch (reader.peek()) {
            case BEGIN_OBJECT: {
                if (depth >= MAX_DEPTH) throw new PaymosException("nested deeper than " + MAX_DEPTH + " levels");
                JsonObject object = new JsonObject();
                reader.beginObject();
                while (reader.hasNext()) {
                    String name = reader.nextName();
                    if (object.has(name)) throw new PaymosException("duplicate key \"" + name + "\"");
                    object.add(name, read(reader, depth + 1));
                }
                reader.endObject();
                return object;
            }
            case BEGIN_ARRAY: {
                if (depth >= MAX_DEPTH) throw new PaymosException("nested deeper than " + MAX_DEPTH + " levels");
                JsonArray array = new JsonArray();
                reader.beginArray();
                while (reader.hasNext()) array.add(read(reader, depth + 1));
                reader.endArray();
                return array;
            }
            case STRING:
                return new JsonPrimitive(reader.nextString());
            case NUMBER:
                // Exactly its digits — never through a double.
                return new JsonPrimitive(new BigDecimal(reader.nextString()));
            case BOOLEAN:
                return new JsonPrimitive(reader.nextBoolean());
            case NULL:
                reader.nextNull();
                return JsonNull.INSTANCE;
            default:
                throw new PaymosException("unexpected " + reader.peek());
        }
    }
}
