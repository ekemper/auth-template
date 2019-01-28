const state = {
    googleUser: null
};

const getters = {
    googleUser: state => {
        return state.googleUser;
    }
};

const actions = {
};

const mutations = {
    setGoogleUser (state, newGoogleUser) {
        state.googleUser = newGoogleUser;
    }
};

export default {
    namespaced: true,
    state,
    getters,
    actions,
    mutations
};