
const state = {
    all: {}
};

const getters = {
    all: state => state.all
};

const actions = {
    fetch: () => {

    }

};

const mutations = {
    setAll: (state, payload) => {
        state.all = payload;
    }
};

export default {
    namespaced: true,
    state,
    getters,
    actions,
    mutations
};