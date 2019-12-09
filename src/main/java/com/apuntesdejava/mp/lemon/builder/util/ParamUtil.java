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
package com.apuntesdejava.mp.lemon.builder.util;

import java.lang.reflect.InvocationTargetException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.ConstructorUtils;

/**
 *
 * @author Diego Silva Limaco <diego.silva at apuntesdejava.com>
 */
public class ParamUtil {

    private static final Logger LOG = Logger.getLogger(ParamUtil.class.getName());

    private final String separator = "=";
    private final Map<String, ParamOption> options = new LinkedHashMap<>();

    public String getHelp() {
        StringBuilder sb = new StringBuilder();
        options.values().forEach((opt) -> {
            sb.append('\t').append(opt.getParam()).append('\t')
                    .append(opt.getDescription());
            if (StringUtils.isNotBlank(opt.getDefaultValue())) {
                sb.append(" (Default value:").append(opt.getDefaultValue()).append(')');
            }
            sb.append('\n');
        });
        return sb.toString();
    }

    public ParamUtil addOption(ParamOption opt) {
        options.put(opt.getParam(), opt);
        return this;
    }

    public <T> T evaluate(Class<T> clazz, String[] args) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Map<String, String> values = new LinkedHashMap<>();
        for (String arg : args) {
            String key = StringUtils.substringBefore(arg, separator);
            String value = StringUtils.substringAfter(arg, separator);
            values.put(key, value);
        }
        if (values.containsKey("--help")) {
            System.out.println(getHelp());
            return null;
        }
        T bean = ConstructorUtils.invokeConstructor(clazz);
        options.entrySet().forEach((e) -> {
            try {
                String key = e.getKey();
                String value = values.get(key);
                ParamOption opt = e.getValue();
                String valueReturn;
                if (value == null) {
                    valueReturn = opt.getDefaultValue();
                } else {
                    valueReturn = value;
                }
                if (opt.getConverter() == null) {
                    PropertyUtils.setProperty(bean, opt.getProperty(), valueReturn);
                } else {
                    PropertyUtils.setProperty(bean, opt.getProperty(), opt.getConverter().apply(valueReturn));

                }
            } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
                LOG.log(Level.SEVERE, null, ex);
            }

        });

        return bean;
    }
}
