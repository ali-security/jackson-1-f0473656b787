package org.codehaus.jackson.map.jsontype;

import java.util.List;

import org.codehaus.jackson.annotate.JsonTypeInfo;
import org.codehaus.jackson.map.BaseMapTest;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

/**
 * Regression test for CVE-2019-10202: with default typing enabled, Jackson must
 * refuse to deserialize known dangerous "gadget" classes. Without the
 * SubTypeValidator blocklist an attacker can supply a polymorphic type id such
 * as {@code com.sun.rowset.JdbcRowSetImpl} and trigger a JNDI/LDAP lookup (and
 * from there remote code execution) purely from untrusted JSON.
 *
 * <p>With {@code DefaultTyping.NON_FINAL} the wire format for a polymorphic
 * value read as {@code Object} is a WRAPPER_ARRAY: {@code ["<fqcn>", <value>]}.
 * That is exactly the shape of the published exploit payloads.
 *
 * <p>Also covers the generic (canonical) type id path of
 * <code>ClassNameIdResolver</code> ([databind#1735]): a type id containing
 * type parameters must still be assignment-compatible with the declared
 * base type.
 */
public class TestPolymorphicDeserGadgetBlocking
    extends BaseMapTest
{
    /**
     * Abstract polymorphic base type using class-name type ids, so that the
     * type id is fully controlled by the incoming JSON.
     */
    @JsonTypeInfo(use=JsonTypeInfo.Id.CLASS, include=JsonTypeInfo.As.WRAPPER_ARRAY)
    static abstract class AbstractBase { }

    private ObjectMapper defaultTypingMapper()
    {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }

    /**
     * The core exploit: a blocklisted gadget class name supplied as the type id
     * of a default-typed value must be rejected with a JsonMappingException that
     * mentions the security block. On unpatched 1.9.13 this instead attempts to
     * construct JdbcRowSetImpl (the gadget), so the throw is the fix's signal.
     */
    public void testGadgetClassIsBlocked() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();

        final String gadget = "com.sun.rowset.JdbcRowSetImpl";
        String json = "[\"" + gadget + "\",{\"dataSourceName\":\"ldap://127.0.0.1:1389/a\",\"autoCommit\":true}]";

        try {
            mapper.readValue(json, Object.class);
            fail("Should not have deserialized blocklisted gadget class " + gadget);
        } catch (JsonMappingException e) {
            verifyException(e, "prevented for security reasons");
        }
    }

    /**
     * A second, independent JDK-provided gadget
     * ({@code java.util.logging.FileHandler}, [databind#1737]) is also on the
     * blocklist and must be rejected. Using a JDK class keeps the test free of
     * extra dependencies while still proving the blocklist path fires.
     */
    public void testSecondGadgetClassIsBlocked() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();

        final String gadget = "java.util.logging.FileHandler";
        String json = "[\"" + gadget + "\",{}]";

        try {
            mapper.readValue(json, Object.class);
            fail("Should not have deserialized blocklisted gadget class " + gadget);
        } catch (JsonMappingException e) {
            verifyException(e, "prevented for security reasons");
        }
    }

    /**
     * Guardrail: a perfectly ordinary, non-blocklisted bean must still
     * round-trip via default typing. Proves the fix does not over-block.
     */
    public void testLegitimateBeanStillWorks() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();

        Object[] input = new Object[] { "hello" };
        String json = mapper.writeValueAsString(input);
        Object[] result = mapper.readValue(json, Object[].class);
        assertEquals(1, result.length);
        assertEquals("hello", result[0]);
    }

    /**
     * [databind#1735]: a generic (canonical) type id is resolved through
     * <code>TypeFactory.constructFromCanonical</code>, bypassing the
     * subtype specialization done for plain class names. Without the
     * assignment-compatibility check such an id may name any class at all,
     * regardless of the declared base type.
     */
    public void testGenericTypeIdNotSubtypeIsRejected() throws Exception
    {
        ObjectMapper mapper = new ObjectMapper();
        String json = "[\"java.util.ArrayList<java.lang.String>\",[\"a\",\"b\"]]";

        try {
            Object result = mapper.readValue(json, AbstractBase.class);
            fail("Should not have accepted generic type id that is not a subtype of base type; got " + result);
        } catch (Exception e) {
            verifyException(e, "not subtype of");
        }
    }

    /**
     * A generic type id must not be usable to smuggle a blocklisted gadget
     * class in as a type parameter either.
     */
    public void testGadgetAsGenericTypeParameterIsBlocked() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();

        final String gadget = "com.sun.rowset.JdbcRowSetImpl";
        String json = "[\"java.util.ArrayList<" + gadget + ">\",[[\"" + gadget + "\",{}]]]";

        try {
            mapper.readValue(json, Object.class);
            fail("Should not have deserialized blocklisted gadget class " + gadget);
        } catch (JsonMappingException e) {
            verifyException(e, "prevented for security reasons");
        }
    }

    /**
     * Guardrail: a generic type id that IS assignment-compatible with the base
     * type must still be accepted.
     */
    public void testGenericTypeIdSubtypeStillWorks() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();
        String json = "[\"java.util.ArrayList<java.lang.String>\",[\"a\",\"b\"]]";

        Object result = mapper.readValue(json, Object.class);
        assertTrue(result instanceof List<?>);
        List<?> list = (List<?>) result;
        assertEquals(2, list.size());
        assertEquals("a", list.get(0));
        assertEquals("b", list.get(1));
    }
}
