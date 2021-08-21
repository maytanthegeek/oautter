export {};

declare global {
  namespace NodeJS {
    interface Global {
      config: ConfigType;
    }
  }

  var config: ConfigType;
}