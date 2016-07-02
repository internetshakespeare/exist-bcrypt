package ca.terpstra.max.exist_bcrypt;

import java.util.Map;
import java.util.List;
import org.exist.xquery.*;
import org.exist.xquery.value.*;
import org.exist.dom.QName;


/**
 * BCrypt password hashing module
 */
public class BCryptModule extends AbstractInternalModule {
    public final static String NAMESPACE_URI = "http://max.terpstra.ca/ns/exist-bcrypt";
    public final static String PREFIX = "bcrypt";
    public final static String DESCRIPTION = "BCrypt password hashing module";
    public final static QName DEFAULT_WORK_VAR = new QName("DEFAULT_WORK", NAMESPACE_URI);
    public final static int DEFAULT_WORK = 10;

    private final static FunctionDef[] functions = {
        new FunctionDef(BCryptMatchesFunction.SIGNATURE, BCryptMatchesFunction.class),
        new FunctionDef(BCryptHashFunction.SIGNATURES[0], BCryptHashFunction.class),
        new FunctionDef(BCryptHashFunction.SIGNATURES[1], BCryptHashFunction.class)
    };

    public BCryptModule() {
        this(null);
    }
    public BCryptModule(Map<String, List<?>> parameters) {
        super(functions, parameters);
        VariableImpl work = new VariableImpl(DEFAULT_WORK_VAR);
        work.setValue(new IntegerValue((long)DEFAULT_WORK));
        mGlobalVariables.put(DEFAULT_WORK_VAR, work);
    }

    @Override
    public String getNamespaceURI() {
        return NAMESPACE_URI;
    }
    @Override
    public String getDefaultPrefix() {
        return PREFIX;
    }
    @Override
    public String getDescription() {
        return DESCRIPTION;
    }
    @Override
    public String getReleaseVersion() {
        return ""; // FIXME?
    }
    
}
