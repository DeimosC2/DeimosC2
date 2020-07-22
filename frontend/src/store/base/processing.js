class Processing {
  constructor() {
    this.state = {
      fetching: false,
      fetchError: null,

      saving: false,
      saveError: null
    };

    this.mutations = {
      fetching(state, fetching) {
        state.fetching = fetching;
      },
      fetchError(state, fetchError) {
        state.fetchError = fetchError;
      },
      clearFetcher(state) {
        state.fetching = false;
        state.fetchError = null;
      },
      saving(state, saving) {
        state.saving = saving;
      },
      saveError(state, saveError) {
        state.saveError = saveError;
      },
      clearSaver(state) {
        state.saving = false;
        state.saveError = null;
      }
    };
  }
}

export default Processing;
