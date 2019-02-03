import axios from 'axios';

const instance = axios.create({
    baseURL: 'https://localhost:4001/',
    timeout: 5000,
});

const state = {
    instance
};

const getters = {
};

const actions = {
    req: async ({ state }, { options }) => {

        options.url = state.baseURL + options.path;

        debugger;
        try {
            return await state.instance(options);
        } catch (error) {
            console.warn(error);
        }
    }
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
    getters,
    actions,
    mutations
};