const state = {
    googleUser: null,
    healthCheck: null
};

const getters = {
    googleUser: state => {
        return state.googleUser;
    },
    healthCheck: state => {
        return state.healthCheck;
    }
};

const actions = {
    logout: (context) => {

        // TODO : make api call to google to revoke token

        localStorage.removeItem('googleUser');
        context.commit('removeGoogleUser');
    },
    checkForLoggedInUser (context) {

        const storedGoogleUser = localStorage.getItem('googleUser');

        if (!context.state.googleUser && storedGoogleUser) {
            const storedValue = JSON.parse(storedGoogleUser);
            context.commit('setGoogleUser', storedValue);
        }
    },
    parseGoogleUser (context, { rawGoogleUser }) {
        const parsedUser = {
            El: rawGoogleUser.El,
            tokenData: rawGoogleUser.Zi,
            Eea: rawGoogleUser.Eea,
            profileImage: rawGoogleUser.w3.Paa,
            email: rawGoogleUser.w3.U3,
            fullName: rawGoogleUser.w3.ig,
            firstName: rawGoogleUser.w3.ofa,
            lastName: rawGoogleUser.w3.wea
        };

        context.commit('setGoogleUser', parsedUser);
    },
    fetchHealthCheck ({ dispatch }) {
        dispatch('api/req', {
            path: '/health-check',
            method: 'get'
        });


        //const healthResponse = await axios.get('/health-check');


        //     try{ 
        //         this.healthStatus = healthResponse.data.message;
        //     }catch(error){
        //         // eslint-disable-next-line
        //   console.warn('error getting server health check',{error})
        //     }
    }
};

const mutations = {
    setGoogleUser (state, googleUser) {
        if (!googleUser || !(Object.keys(googleUser)).length) {
            state.googleUser = null;
            localStorage.removeItem('googleUser');
            return;
        }

        state.googleUser = googleUser;
        localStorage.setItem('googleUser', JSON.stringify(googleUser));
    },
    removeGoogleUser (state) {
        state.googleUser = null;
    }
};

export default {
    namespaced: true,
    state,
    getters,
    actions,
    mutations
};