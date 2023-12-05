#include "baseHelper.hpp"

#include <base/utils/stringUtils.hpp>
#include <fmt/format.h>

#include "builders/utils.hpp"
#include "helperParser.hpp"

namespace builder::builders
{

OpBuilder buildType(const OpBuilder& builder,
                    const Reference& targetField,
                    std::shared_ptr<ValidationToken> validatorToken,
                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (validatorToken->isFull())
    {
        if (validatorToken->hasValue())
        {
            auto resp = buildCtx->validator().getRuntimeValidator(targetField.dotPath());
            if (base::isError(resp))
            {
                return builder;
            }

            auto runValidator = base::getResponse<schemval::RuntimeValidator>(resp);
            if (runValidator(validatorToken->jValue()))
            {
                return builder;
            }

            throw std::runtime_error(fmt::format(
                "Value '{}' fails validation for field '{}'", validatorToken->jValue().str(), targetField.dotPath()));
        }
        else if (validatorToken->hasType())
        {
            // TODO add overloaded validate method
            // auto resp = buildCtx->validator().validate(targetField.dotPath(), validatorToken->sType());
            // if (base::isError(resp))
            // {
            //     throw std::runtime_error(base::getResponse<std::string>(resp));
            // }

            return builder;
        }
        else
        {
            // TODO: this should be unreachable
            throw std::runtime_error("Validation token is full but has no type or value");
        }
    }
    else if (validatorToken->isPartial())
    {
        auto resp = buildCtx->validator().validate(targetField.dotPath(), validatorToken->jType());
        if (base::isError(resp))
        {
            throw std::runtime_error(base::getError(resp).message);
        }

        return builder;
    }

    // Default case, no validation can be done
    return builder;
}

OpBuilder runType(const OpBuilder& builder,
                  const Reference& targetField,
                  const std::shared_ptr<ValidationToken>& validatorToken,
                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // If the builder is not a MapBuilder, do not wrap it
    if (builder.index() != 0)
    {
        return builder;
    }

    // If the builder does not need runtime validation, do not wrap it
    if (!validatorToken->needsRuntimeValidation())
    {
        return builder;
    }

    // Get runtime validator for target field if has any
    auto runValidator = buildCtx->validator().getRuntimeValidator(targetField.dotPath());
    if (base::isError(runValidator))
    {
        return builder;
    }

    // Wrapper Builder
    return [builder = std::get<0>(builder),
            targetField,
            runValidator = base::getResponse<schemval::RuntimeValidator>(runValidator)](
               const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        auto mapOp = builder(opArgs, buildCtx);

        // Wrapper MapOp
        const auto& invalidTrace = fmt::format("{} -> failed type validation", buildCtx->context().opName);
        return [invalidTrace, mapOp, runValidator, runState = buildCtx->runState()](base::ConstEvent event) -> MapResult
        {
            auto mapRes = mapOp(event);
            if (mapRes.failure())
            {
                return std::move(mapRes);
            }

            const auto& value = mapRes.payload();

            auto valid = runValidator(value);
            if (!valid)
            {
                RETURN_FAILURE(runState, json::Json(), invalidTrace);
            }

            return std::move(mapRes);
        };
    };
}

TransformBuilder filterToTransform(const FilterBuilder& builder)
{
    return [builder](const Reference& targetField,
                     const std::vector<OpArg>& opArgs,
                     const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        auto filterOp = builder(targetField, opArgs, buildCtx);

        // Wrapper TransformOp
        return [filterOp](base::Event event) -> TransformResult
        {
            auto filterRes = filterOp(event);
            if (filterRes.failure())
            {
                return base::result::makeFailure<base::Event>(event, filterRes.popTrace());
            }

            return base::result::makeSuccess(std::move(event), filterRes.popTrace());
        };
    };
}

TransformBuilder mapToTransform(const MapBuilder& builder, const Reference& targetField)
{
    return [builder, targetField](const Reference&,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        auto mapOp = builder(opArgs, buildCtx);

        // Wrapper TransformOp
        return [mapOp, targetField](base::Event event) -> TransformResult
        {
            auto mapRes = mapOp(event);
            if (mapRes.failure())
            {
                return base::result::makeFailure<base::Event>(event, mapRes.popTrace());
            }

            event->set(targetField.jsonPath(), mapRes.popPayload());

            return base::result::makeSuccess(event, mapRes.popTrace());
        };
    };
}

TransformBuilder toTransform(const OpBuilder& builder, const Reference& targetField)
{
    switch (builder.index())
    {
        case 0: return mapToTransform(std::get<0>(builder), targetField); // MapBuilder
        case 1: return std::get<1>(builder);                              // TransformBuilder
        case 2: return filterToTransform(std::get<2>(builder));           // FilterBuilder
        default: throw std::runtime_error("Invalid builder type");
    }
}

base::Expression toExpression(const TransformOp& op, const std::string& name)
{
    return base::Term<base::EngineOp>::create(name, op);
}

base::Expression baseHelperBuilder(const std::string& helperName,
                                   const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Obtain the builder
    auto resp = buildCtx->registry().get<OpBuilderEntry>(helperName);
    if (base::isError(resp))
    {
        throw std::runtime_error(fmt::format("Operation builder '{}' not found", helperName));
    }

    auto [validatorToken, builder] = base::getResponse<OpBuilderEntry>(resp);
    // Resolve validator if needed
    if (validatorToken->isDynamic())
    {
        validatorToken = validatorToken->resolve(opArgs);
    }

    // Set operation name
    std::vector<std::string> opArgsStr;
    std::transform(
        opArgs.begin(), opArgs.end(), std::back_inserter(opArgsStr), [](const OpArg& arg) { return arg->str(); });
    auto opArgsStrJoined = base::utils::string::join(opArgsStr, ", ");
    auto name = fmt::format("{}: {}", targetField.dotPath(), helperName);
    if (!opArgsStrJoined.empty())
    {
        name += fmt::format("({})", opArgsStrJoined);
    }

    // Set new context
    auto newBuildCtx = buildCtx->clone();
    newBuildCtx->context().opName = name;

    // Apply wrappers
    base::Expression op;
    try
    {
        auto finalBuilder = toTransform(
            buildType(
                runType(builder, targetField, validatorToken, newBuildCtx), targetField, validatorToken, newBuildCtx),
            targetField);

        op = toExpression(finalBuilder(targetField, opArgs, newBuildCtx), name);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to build operation '{}': {}", name, e.what()));
    }

    return op;
}

base::Expression
baseHelperBuiler(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx, HelperType helperType)
{
    if (!definition.isObject())
    {
        throw std::runtime_error(fmt::format("Expected 'object' type for operation definition, got '{}'",
                                             json::Json::typeToStr(definition.type())));
    }

    if (!definition.size() == 1)
    {
        throw std::runtime_error(
            fmt::format("Expected operation definition to have 1 key, got '{}'", definition.size()));
    }

    auto defObj = definition.getObject().value();

    const auto& [targetStr, jValue] = defObj[0];
    Reference targetField(targetStr);
    std::vector<OpArg> opArgs;
    std::string helperName;

    if (jValue.isBool() || jValue.isNumber())
    {
        // Default helper names
        switch (helperType)
        {
            case HelperType::MAP: helperName = "map"; break;
            case HelperType::FILTER: helperName = "filter"; break;
            default: throw std::runtime_error("Invalid helper type");
        }

        opArgs.emplace_back(std::make_shared<Value>(json::Json(jValue)));
    }
    else if (jValue.isString())
    {
        auto parser = internals::getHelperParser(true);
        auto parseRes = parser(jValue.getString().value(), 0);

        if (parseRes.failure())
        {
            throw std::runtime_error(fmt::format("Failed to parse helper definition '{}'", jValue.getString().value()));
        }

        auto helperToken = parseRes.value();
        if (helperToken.name.empty())
        {
            // Default helper names
            switch (helperType)
            {
                case HelperType::MAP: helperName = "map"; break;
                case HelperType::FILTER: helperName = "filter"; break;
                default: throw std::runtime_error("Invalid helper type");
            }
        }
        else
        {
            helperName = helperToken.name;
        }
        opArgs = helperToken.args;
    }
    else if (jValue.isArray() || jValue.isObject())
    {
        // TODO: recursive call
    }
    else // Null
    {
        throw std::runtime_error(
            fmt::format("Invalid type for operation definition, got '{}'", json::Json::typeToStr(jValue.type())));
    }

    auto expression = baseHelperBuilder(helperName, targetField, opArgs, buildCtx);
    return expression;
}

} // namespace builder::builders
