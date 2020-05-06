import logging

from wallarm_api.log import logger


class _Decorators:
    @classmethod
    def try_decorator(cls, fn):

        async def decorated(*args, **kw):
            for _ in range(5):
                try:
                    value = fn(*args, **kw)
                except Exception as err:
                    logger.error(f'The function "{fn.__name__}" failed\n{err}')
                    continue
                else:
                    break
            else:
                raise Exception(f'Function "{fn.__name__}" somehow did not work for 5 times')
            return await value

        return decorated
