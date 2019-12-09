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

import java.util.function.Function;

/**
 *
 * @author Diego Silva Limaco <diego.silva at apuntesdejava.com>
 */
public class ParamOption {

    private final String property;
    private final String param;
    private String defaultValue;
    private String description;
    private String[] options;
    private Function converter;

    public ParamOption(String property, String param) {
        this.property = property;
        this.param = param;
    }

    public ParamOption(String property, String param, String defaultValue) {
        this.property = property;
        this.param = param;
        this.defaultValue = defaultValue;
    }

    public ParamOption(String property, String param, String defaultValue, String description) {
        this.property = property;
        this.param = param;
        this.defaultValue = defaultValue;
        this.description = description;
    }

    public ParamOption(String property, String param, String defaultValue, String description, Function converter) {
        this.property = property;
        this.param = param;
        this.defaultValue = defaultValue;
        this.description = description;
        this.converter = converter;
    }

    public ParamOption(String property, String param, String defaultValue, String description, String[] options) {
        this.property = property;
        this.param = param;
        this.defaultValue = defaultValue;
        this.description = description;
        this.options = options;
    }

    public ParamOption(String property, String param, String defaultValue, String description, String[] options, Function converter) {
        this.property = property;
        this.param = param;
        this.defaultValue = defaultValue;
        this.description = description;
        this.options = options;
        this.converter = converter;
    }

    public String getDefaultValue() {
        return defaultValue;
    }

    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String[] getOptions() {
        return options;
    }

    public void setOptions(String[] options) {
        this.options = options;
    }

    public String getProperty() {
        return property;
    }

    public String getParam() {
        return param;
    }

    public Function getConverter() {
        return converter;
    }

    public void setConverter(Function converter) {
        this.converter = converter;
    }

}
