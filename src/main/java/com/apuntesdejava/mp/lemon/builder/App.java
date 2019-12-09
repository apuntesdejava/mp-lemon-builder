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

import com.apuntesdejava.mp.lemon.builder.bean.ProjectConfig;
import com.apuntesdejava.mp.lemon.builder.util.ParamOption;
import com.apuntesdejava.mp.lemon.builder.util.ParamUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyRep.Type;
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
import java.util.Set;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.json.Json;
import javax.json.JsonArray;
import org.apache.commons.io.FileUtils;
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

    private static final String TEMPLATE_URL = "https://github.com/apuntesdejava/mp-lemon-builder/blob/master/src/main/resources/mp-lemon-template.zip?raw=true";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        ParamUtil paramUtil = new ParamUtil()
                .addOption(new ParamOption("groupId", "--group-id", "apuntesdejava.com", "Grupo del proyecto"))
                .addOption(new ParamOption("projectName", "--project-name", "example-project", "Nombre del proyecto "))
                .addOption(new ParamOption("version", "--version", "1.0.0-SNAPSHOT", "Nombre del proyecto"))
                .addOption(new ParamOption("webAppName", "--web-app", "webapp-example", "Aplicación base que estará asegurada "))
                .addOption(new ParamOption("jwtProviderName", "--jwt-provider", "jwt-provider-example", "Aplicación web que generara token"))
                .addOption(new ParamOption("realmName", "--realm-name", "realm-example", "Realm configurado en el contenedor"))
                .addOption(new ParamOption("headerKey", "--header-key", "header-key-example", "Clave de la cabecera del token"))
                .addOption(new ParamOption("issuer", "--issuer", "http://example.com", "Issuer del JWT"))
                .addOption(new ParamOption("validToken", "--expires", "100000", "Tiempo de expiración", (Function<String, Long>) (String t) -> NumberUtils.toLong(t)))
                .addOption(new ParamOption("roles", "--roles", "admin,user", "Lista de roles a considerar", (Function<String, Set<String>>) (String t) -> new LinkedHashSet<>(Arrays.asList(StringUtils.split(t, ",")))))
                .addOption(new ParamOption("outputDir", "--output-project", "output-project", "Ubicación de la ruta a generar el proyecto"));
        ProjectConfig proj = paramUtil.evaluate(ProjectConfig.class, args);
        if (proj != null) {
            String outputDir = proj.getOutputDir();

            Path template = getTemplatePath();

            new App().execute(proj, outputDir, template.toString());
        }

    }

    private static Path getTemplatePath() throws MalformedURLException, IOException {
        File tempFile = File.createTempFile("lemon", "zip");
        tempFile.deleteOnExit();
        FileUtils.copyURLToFile(new URL(TEMPLATE_URL), tempFile);

        Path tempDir = Files.createTempDirectory("lemon");

        byte[] buffer = new byte[1024];
        try ( ZipInputStream zis = new ZipInputStream(new FileInputStream(tempFile))) {
            ZipEntry zipEntry = zis.getNextEntry();
            while (zipEntry != null) {
                String entryName = zipEntry.getName();
                LOGGER.log(Level.INFO, "->{0}", entryName);
                if (zipEntry.isDirectory()) {
                    Path dir = Paths.get(tempDir.toString(), entryName);
                    Files.createDirectories(dir);
                } else {
                    String[] fileName = entryName.split("/");
                    Path file = Paths.get(tempDir.toString(), fileName);
                    try ( FileOutputStream fos = new FileOutputStream(file.toFile())) {
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
                zipEntry = zis.getNextEntry();
            }
            zis.closeEntry();
        }
        return Paths.get(tempDir.toString(), "mp-lemon-template");

    }

    private final Map<java.security.KeyRep.Type, String> keys;

    private App() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        this.keys = generateKeys();
    }

    private void execute(ProjectConfig proj, String output, String template) throws IOException {
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
            String.valueOf(proj.getValidToken()),
            proj.getIssuer(),
            proj.getHeaderKey(),
            keys.get(PUBLIC),
            keys.get(PRIVATE),
            payaraRoles.toString(),
            proj.getRealmName(),
            webRoles.toString()
        };

        Path templateList = Paths.get(template, "list.txt");
        List<String> files = Files.readAllLines(templateList);
        Map<String, Path> projectStructure = new LinkedHashMap<>();
        Map<String, Path> projectStructureTemplate = new LinkedHashMap<>();

        Path projectDir = Paths.get(output, proj.getProjectName());

        files.forEach(
                (file) -> {
                    LOGGER.info(file);
                    projectStructureTemplate.put(file, Paths.get(template, file));
                    projectStructure.put(file, Paths.get(projectDir.toString(), file));
                }
        );
        LOGGER.info("Creando estructura de directorios...");
        projectStructure.entrySet()
                .forEach((entry) -> {
                    try {
                        String fileName = entry.getKey();

                        Path source = projectStructureTemplate.get(entry.getKey());
                        String contents = new String(Files.readAllBytes(source));
                        String newContents = StringUtils.replaceEach(contents, searchList, replaceList);
                        Path targetFile = entry.getValue();
                        Path parent = targetFile.getParent();
                        if (StringUtils.endsWith(fileName, ".java")) {
                            String packageName = StringUtils.substringBetween(newContents, "package ", ";");
                            String[] packageDir = StringUtils.split(packageName, '.');
                            parent = Paths.get(targetFile.getParent().toString(), packageDir);
                            String javaFileName = targetFile.getName(targetFile.getNameCount() - 1).toString();
                            targetFile = Paths.get(parent.toString(), javaFileName);
                        }
                        Files.createDirectories(parent);
                        Files.write(targetFile, newContents.getBytes());

                    } catch (IOException ex) {
                        LOGGER.severe(ex.getMessage());
                    }
                });
        LOGGER.info("...Terminado");
    }

    private static Map<Type, String> generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PKCS8EncodedKeySpec encoded = new PKCS8EncodedKeySpec(publicKey.getEncoded());

        byte[] privateKeyString = toByte(privateKey);
        byte[] publicKeyString = toByte(encoded.getEncoded());
        Map<Type, String> map = new LinkedHashMap<>();
        map.put(PRIVATE, new String(privateKeyString));
        map.put(PUBLIC, new String(publicKeyString));
        return map;
    }

    static byte[] toByte(Key key) {
        return Base64.getEncoder().encode(key.getEncoded());
    }

    static byte[] toByte(byte[] content) {
        return Base64.getEncoder().encode(content);
    }

}
