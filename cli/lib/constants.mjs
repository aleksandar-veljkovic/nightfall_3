// eslint-disable-next-line import/prefer-default-export
export const ENVIRONMENTS = {
  mainnet: {
    name: 'Mainnet',
    chainId: 1,
    clientApiUrl: '',
    optimistApiUrl: '',
    optimistWsUrl: '',
  },
  ropsten: {
    name: 'Ropsten',
    chainId: 3,
    clientApiUrl: 'https://client1.testnet.nightfall3.com',
    optimistApiUrl: 'https://optimist1.testnet.nightfall3.com',
    optimistWsUrl: 'wss://optimist1-ws.testnet.nightfall3.com',
  },
  rinkeby: {
    name: 'Rinkeby',
    chainId: 4,
    clientApiUrl: '',
    optimistApiUrl: '',
    optimistWsUrl: '',
  },
  localhost: {
    name: 'Localhost',
    chainId: 4378921,
    clientApiUrl: 'http://localhost:8080',
    optimistApiUrl: 'http://localhost:8081',
    optimistWsUrl: 'ws://localhost:8082',
  },
};