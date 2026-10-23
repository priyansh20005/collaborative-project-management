const { app, bootstrap } = require('./app');

const port = process.env.PORT || 3000;

bootstrap().then(() => {
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server is running on port ${port}`);
  });
});
