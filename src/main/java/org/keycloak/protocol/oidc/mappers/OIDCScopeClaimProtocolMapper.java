package org.keycloak.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.rar.AuthorizationRequestContext;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

public class OIDCScopeClaimProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    private static final String SCOPE = "scope";

    private static final String SCOPE_LABEL = "oidc-scope-claim-protocol-mapper.scope.label";
    private static final String SCOPE_HELP_TEXT = "oidc-scope-claim-protocol-mapper.scope.tooltip";

    public static final String PROVIDER_ID = "oidc-scope-claim-protocol-mapper";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty scopeProperty = new ProviderConfigProperty();
        scopeProperty.setName(SCOPE);
        scopeProperty.setLabel(SCOPE_LABEL);
        scopeProperty.setRequired(true);
        scopeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        scopeProperty.setHelpText(SCOPE_HELP_TEXT);

        configProperties.add(scopeProperty);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, OIDCScopeClaimProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Scope-based claim mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getHelpText() {
        return "Map scope dynamic value to claim";
    }

    @Override
    protected void setClaim(IDToken idToken, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        String claimValue = getClaimValue(mappingModel, userSession, clientSessionCtx);
        if (claimValue != null) {
            OIDCAttributeMapperHelper.mapClaim(idToken, mappingModel, claimValue);
        }
    }

    @Override
    protected void setClaim(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession,
            ClientSessionContext clientSessionCtx) {
        String claimValue = getClaimValue(mappingModel, userSession, clientSessionCtx);
        if (claimValue != null) {
            OIDCAttributeMapperHelper.mapClaim(accessTokenResponse, mappingModel, claimValue);
        }
    }

    private static String getClaimValue(ProtocolMapperModel mappingModel, UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        AuthorizationRequestContext authorizationRequestContext = clientSessionCtx.getAuthorizationRequestContext();

        String scopeName = mappingModel.getConfig().get(SCOPE);
        return authorizationRequestContext.getAuthorizationDetailEntries()
                .stream()
                .filter(d -> d.getClientScope().getName().equals(scopeName))
                .map(d -> d.getDynamicScopeParam())
                .findFirst().orElse(null);
    }

    public static ProtocolMapperModel createClaimMapper(String name,
            String tokenClaimName,
            boolean consentRequired, String consentText,
            boolean accessToken, boolean idToken) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<String, String>();
        config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, tokenClaimName);

        if (accessToken) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        }

        if (idToken) {
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        }

        mapper.setConfig(config);
        return mapper;
    }
}
