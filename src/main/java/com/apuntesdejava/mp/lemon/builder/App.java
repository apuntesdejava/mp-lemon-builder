/*
 * Copyright 2019 Diego Silva Limaco <diego.silva at apuntesdejava.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.apuntesdejava.mp.lemon.builder;

import com.apuntesdejava.mp.lemon.builder.bean.Container;
import com.apuntesdejava.mp.lemon.builder.bean.ProjectConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import static java.security.KeyRep.Type.PRIVATE;
import static java.security.KeyRep.Type.PUBLIC;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.json.Json;
import javax.json.JsonArray;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Diego Silva Limaco <diego.silva at apuntesdejava.com>
 */
public class App {

    private static final Logger LOGGER = Logger.getLogger(App.class.getName());

    private static final String TEMPLATE = "e:\\proys\\jakarta\\mp-lemon-template\\";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ParseException {

        Options options = new Options();
        options.addOption("h", "help", false, "Shows help")
                .addOption("g", "group-id", true, "project groupId")
                .addOption("v", "version", true, "project version")
                .addOption("p", "project-name", true, "project Name")
                .addOption("w", "web-app", true, "Web Application Name (authorization)")
                .addOption("j", "jwt-provider", true, "JWT Provider Name (authentication)")
                .addOption("r", "roles", true, "Roles list")
                .addOption("a", "real-name", true, "Realm Name")
                .addOption("h", "header-key", true, "JWT Header Key")
                .addOption("i", "issuer", true, "JWT Issuer")
                .addOption("t", "expires-token", true, "Milliseconds validate token")
                .addOption("o", "output-dir", true, "Path output project generate");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption('h') || cmd.getArgList().isEmpty()) {
            showHelp(options);
        }

        String groupId = cmd.getOptionValue('g', "com.apuntesdejava");
        String version = cmd.getOptionValue('v', "1.0-SNAPSHOT");
        String projectName = cmd.getOptionValue('p', "example-project");
        String webAppName = cmd.getOptionValue('w', "web-app");
        String jwtProviderName = cmd.getOptionValue('j', "jwt-provider");

        String[] roles = ObjectUtils.defaultIfNull(cmd.getOptionValues('r'), new String[]{"web", "admin"});

        String realmName = cmd.getOptionValue('a', "auth-file");

        ProjectConfig proj = new ProjectConfig();
        proj.setGroupId(groupId);
        proj.setVersion(version);
        proj.setProjectName(projectName);
        proj.setWebAppName(webAppName);
        proj.setJwtProviderName(jwtProviderName);
        proj.setRoles(new LinkedHashSet<>(Arrays.asList(roles)));
        proj.setContainer(Container.PAYARA);
        proj.setRealmName(realmName);
        ProjectConfig.JWTConfig jwtConfig = new ProjectConfig.JWTConfig();
        jwtConfig.setHeaderKey(cmd.getOptionValue('h', "my-header-key"));
        jwtConfig.setIssuer(cmd.getOptionValue('i', "my-issuer"));
        jwtConfig.setValidToken(NumberUtils.toLong(cmd.getOptionValue('t'), 10000000L));
        proj.setJwtConfig(jwtConfig);

        String outputDir = cmd.getOptionValue('o', "output-project");

        new App().execute(proj, outputDir);

    }

    private static void showHelp(Options options) {
        System.out.println("Estos son los argumentos:");
        options.getOptions().forEach((opt) -> {
            System.out.println("\t" + opt.getOpt() + "\t" + opt.getDescription());
        });
        System.exit('1');
    }
    private final Map<java.security.KeyRep.Type, String> keys;

    private App() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        this.keys = generateKeys();
    }

    private void execute(ProjectConfig proj, String output) throws IOException {
        String jProjectName = RegExUtils.replaceAll(proj.getProjectName(), "[-]", ".");
        String jWebAppName = RegExUtils.replaceAll(proj.getWebAppName(), "[-]", ".");
        String jJwtProviderName = RegExUtils.replaceAll(proj.getJwtProviderName(), "[-]", ".");
        StringBuilder xmlModules = new StringBuilder();
        xmlModules.append("<module>").append(proj.getWebAppName()).append("</module>");
        xmlModules.append("<module>").append(proj.getJwtProviderName()).append("</module>");
        JsonArray rolesJson = Json.createArrayBuilder(proj.getRoles()).build();

        StringBuilder rolesSB = new StringBuilder().append('{');
        StringBuilder payaraRoles = new StringBuilder();
        StringBuilder webRoles = new StringBuilder();
        String payaraRoleTemplate = "    <security-role-mapping>\n"
                + "        <role-name>ROLE</role-name>\n"
                + "        <group-name>ROLE</group-name>\n"
                + "    </security-role-mapping>\n";
        String webRoleTemplate = "    <security-role>\n"
                + "        <role-name>ROLE</role-name>\n"
                + "    </security-role>\n";
        proj.getRoles().forEach((r) -> {
            rolesSB.append('"').append(r).append('"').append(",");
            payaraRoles.append(RegExUtils.replaceAll(payaraRoleTemplate, "ROLE", r));
            webRoles.append(RegExUtils.replaceAll(webRoleTemplate, "ROLE", r));
        });
        rolesSB.setCharAt(rolesSB.length() - 1, '}');

        String[] searchList = {
            "${groupId}",
            "${projectName}",
            "${version}",
            "${plain.webAppName}",
            "${webAppName}",
            "${jwtProviderName}",
            "${plain.jwtProviderName}",
            "${xml.modules}",
            "${roles}",
            "${json.roles}",
            "${validToken}",
            "${issuer}",
            "${headerKey}",
            "${publicKey}",
            "${privateKey}",
            "${payara-web-roles}",
            "${realmName}",
            "${web-xml-roles}"
        };
        String[] replaceList = {
            proj.getGroupId(),
            jProjectName,
            proj.getVersion(),
            proj.getWebAppName(),
            jWebAppName,
            jJwtProviderName,
            proj.getJwtProviderName(),
            xmlModules.toString(),
            rolesSB.toString(),
            rolesJson.toString(),
            String.valueOf(proj.getJwtConfig().getValidToken()),
            proj.getJwtConfig().getIssuer(),
            proj.getJwtConfig().getHeaderKey(),
            keys.get(PUBLIC),
            keys.get(PRIVATE),
            payaraRoles.toString(),
            proj.getRealmName(),
            webRoles.toString()
        };

        Path templateList = Path.of(TEMPLATE, "list.txt");
        List<String> files = Files.readAllLines(templateList);
        Map<String, Path> projectStructure = new LinkedHashMap<>();
        Map<String, Path> projectStructureTemplate = new LinkedHashMap<>();

        Path projectDir = Path.of(output, proj.getProjectName());

        files.forEach(
                (file) -> {
                    LOGGER.info(file);
                    projectStructureTemplate.put(file, Path.of(TEMPLATE, file));
                    projectStructure.put(file, Path.of(projectDir.toString(), file));
                }
        );
        LOGGER.info("Creando estructura de directorios...");
        projectStructure.entrySet()
                .forEach((entry) -> {
                    try {
                        String fileName = entry.getKey();

                        Path source = projectStructureTemplate.get(entry.getKey());
                        String contents = Files.readString(source);
                        String newContents = StringUtils.replaceEach(contents, searchList, replaceList);
                        Path targetFile = entry.getValue();
                        Path parent = targetFile.getParent();
                        if (StringUtils.endsWith(fileName, ".java")) {
                            String packageName = StringUtils.substringBetween(newContents, "package ", ";");
                            String[] packageDir = StringUtils.split(packageName, '.');
                            parent = Path.of(targetFile.getParent().toString(), packageDir);
                            String javaFileName = targetFile.getName(targetFile.getNameCount() - 1).toString();
                            targetFile = Path.of(parent.toString(), javaFileName);
                        }
                        Files.createDirectories(parent);
                        Files.writeString(targetFile, newContents);

                    } catch (IOException ex) {
                        LOGGER.severe(ex.getMessage());
                    }
                });
        LOGGER.info("...Terminado");
    }

    private static Map<java.security.KeyRep.Type, String> generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PKCS8EncodedKeySpec encoded = new PKCS8EncodedKeySpec(publicKey.getEncoded());

        byte[] privateKeyString = toByte(privateKey);
        byte[] publicKeyString = toByte(encoded.getEncoded());
        return Map.of(PRIVATE, new String(privateKeyString), PUBLIC, new String(publicKeyString));
    }

    static byte[] toByte(Key key) {
        return Base64.getEncoder().encode(key.getEncoded());
    }

    static byte[] toByte(byte[] content) {
        return Base64.getEncoder().encode(content);
    }

}
