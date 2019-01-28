module.exports = {
    root: true,
    parserOptions: {
      parser: 'babel-eslint',
      sourceType: 'module'
    },
  
    env: {
      browser: true,
        "node": true
    },
    extends: ['eslint:recommended', 'plugin:vue/recommended'
    ],
    rules: {
      'no-debugger': process.env.NODE_ENV === 'production' ? 2 : 0,
      'vue/html-indent': [
        'error',
            4,
            {
          attribute: 1,
          closeBracket: 0,
          alignAttributesVertically: true,
          ignores: []
            }
        ],
      quotes: [
            "error",
            "single"
        ],
      indent: [
            "error",
            4
        ],
        "no-console": [
            "error",
            { allow: [
                    "log",
                    "warn",
                    "error"
                ]
            }
        ],
        "no-unused-vars": "warn",
        "no-extra-boolean-cast": 0,
      semi: [
            2,
            "always"
        ]
    }
};
  