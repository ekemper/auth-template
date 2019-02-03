import axios from 'axios';

const BASE_URL = 'http://localhost:4001';

const instance = axios.create({
    BASE_URL,
    timeout: 5000,
});

instance.interceptors.request.use(
    (config) => {
        const googleUser = JSON.parse(localStorage.getItem('googleUser'));
        const token = googleUser.tokenData.id_token;
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }

        return config;
    },

    (error) => {
        return Promise.reject(error);
    }
);

const state = {
    instance,
    BASE_URL,
};

// const getters = {
//     token: state => {
//         debugger;
//         return state.instance.defaults.headers.common['Authorization'];
//     }
// };

const actions = {
    req: async ({ state }, options) => {

        options.url = state.BASE_URL + options.path;

        try {
            return await state.instance(options);
        } catch (error) {
            console.warn(error);
        }
    },
};

const mutations = {
    setToken: (state, payload) => {
        state.instance.defaults.headers.common['Authorization'] = payload.token;
    },
    setBaseUrl: (state, payload) => {
        state.instance.defaults.baseURL = payload.baseURL;
    }
};

export default {
    namespaced: true,
    state,
    //getters,
    actions,
    mutations
};