import logging


class _Decorators:
    @classmethod
    def try_decorator(cls, fn):
        logger = logging.getLogger(__name__)

        async def decorated(*args, **kw):
            for _ in range(5):
                try:
                    value = fn(*args, **kw)
                except Exception as error:
                    logger.log(logging.ERROR, f'The function "{fn.__name__}" failed\n%s', error)
                    continue
                else:
                    break
            else:
                raise Exception(f'Function "{fn.__name__}" somehow did not work for 5 times')
            return await value

        return decorated
