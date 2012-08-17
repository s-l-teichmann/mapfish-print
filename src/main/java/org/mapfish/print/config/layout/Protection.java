package org.mapfish.print.config.layout;

import org.mapfish.print.InvalidValueException;

import java.util.TreeSet;
import java.util.Collection;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.PdfWriter;

public class Protection {

    private TreeSet<String> permissions;

    private boolean encryptMetaData;

    private String encryptionType;

    private String userPassword;
    private String ownerPassword;

    public static final class KV {

        private String key;
        private int    value;

        KV(String key, int value) {
            this.key = key;
            this.value = value;
        }

        public String getKey() {
            return key;
        }

        public int getValue() {
            return value;
        }
    }

    public static final KV [] PERMISSIONS = {
        new KV("assembly", PdfWriter.ALLOW_ASSEMBLY),
        new KV("copy", PdfWriter.ALLOW_COPY),
        new KV("degradedPrinting", PdfWriter.ALLOW_DEGRADED_PRINTING),
        new KV("fillIn", PdfWriter.ALLOW_FILL_IN),
        new KV("modifyAnnotations", PdfWriter.ALLOW_MODIFY_ANNOTATIONS),
        new KV("modifyContebts", PdfWriter.ALLOW_MODIFY_CONTENTS),
        new KV("printing", PdfWriter.ALLOW_PRINTING),
        new KV("screenReaders", PdfWriter.ALLOW_SCREENREADERS)
    };

    public static final KV [] ENCRYPTION_TYPES = {
        new KV("standardEncryption40", PdfWriter.STANDARD_ENCRYPTION_40),
        new KV("standardEncryption128", PdfWriter.STANDARD_ENCRYPTION_128),
        new KV("encryptionAES128", PdfWriter.ENCRYPTION_AES_128)
    };

    public static final KV findKV(String key, KV [] pairs) {
        for (KV pv: pairs) {
            if (key.equalsIgnoreCase(pv.getKey())) {
                return pv;
            }
        }
        return null;
    }

    public static final int allPermissionsMask() {
        int permissions = 0;
        for (KV pv: PERMISSIONS) {
            permissions |= pv.getValue();
        }
        return permissions;
    }

    public static final int permissionsMask(Collection<String> values) {
        int permissions = 0;
        for (String value: values) {
            KV pv = findKV(value, PERMISSIONS);
            if (pv != null) {
                permissions |= pv.getValue();
            }
        }
        return permissions;
    }

    public Protection() {
    }

    public void setPermissions(TreeSet<String> permissions) {
        this.permissions = permissions;
    }

    public TreeSet<String> getPermissions() {
        return permissions;
    }

    public int getPermissionsMask() {
        return permissions != null
            ? permissionsMask(permissions)
            : allPermissionsMask();
    }

    public String getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(String encryptionType) {
        this.encryptionType = encryptionType;
    }

    public String getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
    }

    public String getOwnerPassword() {
        return ownerPassword;
    }

    public void setOwnerPassword(String ownerPassword) {
        this.ownerPassword = ownerPassword;
    }

    public int getEncryptionMask() {
        int mask = 0;
        if (encryptionType != null) {
            KV kv = findKV(encryptionType, ENCRYPTION_TYPES);
            if (kv != null) {
                mask = kv.getValue();
            }
        }

        if (!encryptMetaData) {
            mask |= PdfWriter.DO_NOT_ENCRYPT_METADATA;
        }

        return mask;
    }

    public void validate() {
        if (encryptionType != null) {
            if (findKV(encryptionType, ENCRYPTION_TYPES) == null) {
                throw new InvalidValueException("encryptionType", encryptionType);
            }
        }
        if (permissions != null) {
            for (String key: permissions) {
                if (findKV(key, PERMISSIONS) == null) {
                    throw new InvalidValueException("permissions", key);
                }
            }
        }
    }

    public void configure(PdfWriter writer) throws DocumentException {
        if (userPassword != null 
        || ownerPassword != null
        || permissions != null) {
            byte [] user = userPassword != null
                ? userPassword.getBytes()
                : null;
            byte [] owner = ownerPassword != null
                ? ownerPassword.getBytes()
                : null;
            int permMask = getPermissionsMask();
            int encMask = getEncryptionMask();

            writer.setEncryption(user, owner, permMask, encMask);
        }
    }
}
