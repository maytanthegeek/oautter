export default class HTTPError extends Error {
  private errorCode: number;

  private errorMessage: string;

  private errorDescription?: string;

  constructor(code: number, message: string, description?: string) {
    super(message);
    this.errorCode = code;
    this.errorMessage = message;
    this.errorDescription = description;
  }

  public get code() {
    return this.errorCode;
  }

  public get message() {
    return this.errorMessage;
  }

  public get description() {
    return this.errorDescription;
  }
}
