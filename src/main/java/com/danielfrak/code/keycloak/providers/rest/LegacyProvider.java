package com.danielfrak.code.keycloak.providers.rest;

import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUser;
import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUserService;
import com.danielfrak.code.keycloak.providers.rest.remote.UserModelFactory;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.*;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Provides legacy user migration functionality
 */
public class LegacyProvider implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputUpdater,
        CredentialInputValidator {

    private static final Logger LOG = Logger.getLogger(LegacyProvider.class);
    private static final Set<String> supportedCredentialTypes = Collections.singleton(PasswordCredentialModel.TYPE);
    private final KeycloakSession session;
    private final LegacyUserService legacyUserService;
    private final UserModelFactory userModelFactory;
    private final ComponentModel model;

    public LegacyProvider(KeycloakSession session, LegacyUserService legacyUserService,
                          UserModelFactory userModelFactory, ComponentModel model) {
        this.session = session;
        this.legacyUserService = legacyUserService;
        this.userModelFactory = userModelFactory;
        this.model = model;
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        if (session.getContext().getClient() == null) {
            // for some reason, this plugin gets called even when trying to create users via Keycloak's REST API.
            // This was causing a weird interaction where the following steps happened:
            //   1. Keycloak got request to create a user
            //   2. It decided to use this plugin to see if the user existed in the "external" (updox) storage system
            //   3. If that were true, this plugin would automatically create the user
            //   4. After this plugin executed, we would get back into Keycloak's normal user creation flow, which would
            //      try to create the user *again*. That would fail as there would already be a user in the database
            //      from the plugin with the same username
            //   5. Collie or whoever tried to create the user via API would get a 404 telling them the user could not be
            //      created because it already exists
            // So if the session context client is null (which would only happen on API calls), skip this plugin entirely
            // to ensure the API can do what it needs to do without someone stepping on its toes
            LOG.debug("Skipping legacy user lookup, client was not present in session context");
            return null;
        }

        // this process was kicked off by a user attempting to log into a client that wasn't recognized by Keycloak,
        // look them up in the "legacy" updox user store
        return getUserModel(realm, username, () -> legacyUserService.findByUsername(username));
    }

    private UserModel getUserModel(RealmModel realm, String username, Supplier<Optional<LegacyUser>> user) {
        return user.get()
                .map(u -> userModelFactory.create(u, realm))
                .orElseGet(() -> {
                    LOG.warnf("User not found in external repository: %s", username);
                    return null;
                });
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        return null;
        // we don't support login by email, keeping it commented out for future reference tho
        //return getUserModel(realm, email, () -> legacyUserService.findByEmail(email));
    }

    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        var userIdentifier = getUserIdentifier(userModel);
        var validPassword = legacyUserService.isPasswordValid(userIdentifier, input.getChallengeResponse());
        if (validPassword && shouldMigrateUserPassword()) {
            // don't want to add passwords for users at first, can enable this after
            final PasswordHashProvider hashProvider = session.getProvider(PasswordHashProvider.class, PasswordPolicy.HASH_ALGORITHM_DEFAULT);
            // -1 indicates "use the default number of iterations"
            final PasswordCredentialModel hashedPassword = hashProvider.encodedCredential(input.getChallengeResponse(), -1);
            session.getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID)
                    .createCredential(realmModel, userModel, hashedPassword);
            // break the link to the federation provider
            this.updateCredential(realmModel, userModel, input);
        }

        return validPassword;
    }

    private boolean shouldMigrateUserPassword() {
        return Boolean.parseBoolean(
                model.getConfig().getFirst(ConfigurationProperties.MIGRATE_PASSWORD_PROPERTY)
        );
    }

    private String getUserIdentifier(UserModel userModel) {
        var userIdConfig = model.getConfig().getFirst(ConfigurationProperties.USE_USER_ID_FOR_CREDENTIAL_VERIFICATION);
        var useUserId = Boolean.parseBoolean(userIdConfig);
        return useUserId ? userModel.getId() : userModel.getUsername();
    }

    @Override
    public boolean supportsCredentialType(String s) {
        return supportedCredentialTypes.contains(s);
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        throw new UnsupportedOperationException("User lookup by id not implemented");
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String s) {
        return false;
    }

    @Override
    public void close() {
        legacyUserService.close();
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        String link = user.getFederationLink();
        if (link != null && !link.isBlank()) {
            user.setFederationLink(null);
        }
        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        // Not needed
    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.emptySet();
    }

}
